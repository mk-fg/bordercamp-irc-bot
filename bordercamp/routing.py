# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys

from twisted.internet import reactor, protocol, defer
from twisted.python import log


class BCInterface(object):
	'''Persistent "interface" object sitting in-between persistent relay objects
		and transient protocol objects, queueing/multiplexing messages from
		relays to the protocols and messages/events from protocols to relays.'''

	irc_enc = 'utf-8'
	proto = None

	def __init__(self, dry_run=False):
		self.dry_run = dry_run

	def update(self, relays, channels, routes):

		def resolve(route, k, fork, lvl=0):
			# print(lvl, route.name, k, fork)
			if k not in route: route[k] = list()
			elif isinstance(route[k], str): route[k] = [route[k]]
			modules = list()
			for v in route[k]:
				if v not in routes: modules.append(v)
				else:
					for subroute in routes[v]:
						if fork is None:
							resolve(subroute, k, lvl=lvl+1)
							modules.extend(subroute[k])
						else:
							fork = route.clone()
							fork.pipe = (list(fork.pipe) + subroute.pipe)\
								if fork is True else (subroute.pipe + list(fork.pipe))
							resolve(subroute, k, fork=True, lvl=lvl+1)
							fork[k] = subroute[k]
							routes[route.name].append(fork)
			route[k] = modules

		for name, route in routes.viewitems(): routes[name] = [route]
		for k, fork in ('pipe', None), ('src', True), ('dst', False):
			for name, route_set in routes.items():
				for route in route_set:
					if k == 'pipe':
						for v in route.pipe:
							if v in channels:
								log.fatal( 'Channels are not allowed'
									' in route.pipe sections (route: {}, channel: {})'.format(name, v) )
								sys.exit(1)
					route.name = name
					resolve(route, k, fork=fork)

		pipes, pipes_chk = dict(), set()
		pipes_valid = set(relays).union(channels)
		for route in it.chain.from_iterable(routes.viewvalues()):
			if not route.src or not route.dst: continue
			for src, dst in it.product(route.src, route.dst):
				pipe = tuple([src] + route.pipe + [dst])
				if pipe in pipes_chk: continue
				for v in pipe:
					if v not in pipes_valid:
						log.fatal('Unknown route component (route: {}): {}'.format(route.name, v))
						sys.exit(1)
				pipes_chk.add(pipe) # to eliminate duplicates
				pipes.setdefault(src, list()).append((dst, route.pipe))
		log.noise('Pipelines (by src): {}'.format(pipes))

		# Add reverse (obj -> name) mapping to relays
		for name, relay_obj in relays.items(): relays[relay_obj] = name

		self.relays, self.channels, self.routes = relays, channels, pipes

	def proto_on(self, irc):
		self.proto = irc
		for alias, channel in self.channels.viewitems():
			log.debug('Joining channel: {}'.format(channel.name))
			self.proto.join(channel.name)
	def proto_off(self, irc): self.proto = None

	def proto_msg(self, irc, user, nick, channel, message): pass


	@defer.inlineCallbacks
	def dispatch(self, msg, source):
		if not isinstance(msg, list): msg = [msg]

		# Pull msg through all the pipelines and build dst channels / msgs buffer
		channels = dict()
		for dst, pipe in self.routes[self.relays[source]]:
			msg_copy = list(msg)
			for name in pipe:
				relay = self.relays[name]
				results = yield defer.DeferredList(list(
					defer.maybeDeferred(relay.dispatch, part) for part in msg_copy ))
				msg_copy = set()
				for chk, result in results:
					if not chk:
						log.error(
							'Detected pipeline failure (src: {}, dst: {}, pipe: {}, relay: {}, msg: {}): {}'\
							.format(source, dst, pipe, name, msg_copy, result) )
					elif isinstance(result, list): msg_copy.update(result)
					else: msg_copy.add(result)
				msg_copy = msg_copy.difference({None})
				if not msg_copy: break
			else:
				if dst in self.relays:
					yield defer.DeferredList(list(
						defer.maybeDeferred(dst.dispatch, msg) for msg_copy in msg_copy ))
				else:
					channels.setdefault(self.channels[dst].name, set()).update(msg_copy)

		# Check whether anything can be delivered at all
		if not self.proto: # TODO: queue
			log.warn( 'Failed to deliver message(s)'
				' ({!r}) to the following channels: {}'.format(msg, channels) )
			defer.returnValue(None)

		# Encode and deliver
		for channel, msg in channels.viewitems():
			for msg in msg:
				if not isinstance(msg, str):
					log.warn('Dropping non-str message: {!r}'.format(msg))
					continue
				if isinstance(msg, unicode):
					try: msg = msg.encode(irc_enc)
					except UnicodeEncodeError as err:
						log.warn('Failed to encode ({}) unicode msg ({!r}): {}'.format(irc_enc, msg, err))
						msg = msg.encode(irc_enc, 'replace')
				max_len = self.proto._safeMaximumLineLength('PRIVMSG {} :'.format(channel)) - 2
				first_line = True
				for line in irc.split(msg, length=max_len):
					if not first_line: line = '  {}'.format(line)
					if not self.dry_run: self.proto.msg(channel, line)
					else: log.info('IRC line (channel: {}): {}'.format(channel, line))
					first_line = False
