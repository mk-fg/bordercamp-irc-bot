# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, inspect, types

from twisted.internet import reactor, protocol, defer
from twisted.words.protocols import irc
from twisted.python import log


class BCInterface(object):
	'''Persistent "interface" object sitting in-between persistent relay objects
		and transient protocol objects, queueing/multiplexing messages from
		relays to the protocols and messages/events from protocols to relays.'''

	proto = None

	def __init__(self, irc_enc='utf-8', chan_prefix='#', dry_run=False):
		self.irc_enc, self.chan_prefix, self.dry_run = irc_enc, chan_prefix, dry_run

	def update(self, relays, channels, routes):

		def resolve(route, k, fork=False, lvl=0):
			if k not in route: route[k] = list()
			elif isinstance(route[k], types.StringTypes): route[k] = [route[k]]
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

		for name, route in routes.viewitems():
			if not route.get('pipe'): route.pipe = list()
			route.name = name
			routes[name] = [route]
		for k, fork in ('pipe', None), ('src', True), ('dst', False):
			for name, route_set in routes.items():
				for route in route_set:
					if k == 'pipe':
						for v in route.pipe or list():
							if v in channels:
								log.fatal( 'Channels are not allowed'
									' in route.pipe sections (route: {}, channel: {})'.format(name, v) )
								sys.exit(1)
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

		self.relays, self.channels, self.routes = relays.copy(), channels.copy(), pipes

		# Remove channels that aren't used in any of the routes
		self.channel_map, channels = dict(), set()
		for src, routes in self.routes.viewitems():
			channels.add(src)
			for dst, pipe in routes: channels.add(dst)
		for channel in list(self.channels):
			if channel not in channels:
				log.debug('Ignoring channel, not used in any of the routes: {}'.format(channel))
				del self.channels[channel]
			else:
				alias, channel = channel, self.channels[channel]
				name = channel.get('name') or alias
				self.channel_map[name] = alias


	def proto_on(self, irc):
		self.proto = irc
		for alias, channel in self.channels.viewitems():
			channel = channel.get('name') or alias
			if channel[0] not in self.chan_prefix:
				log.debug( 'Not joining channel'
					' w/o channel-specific prefiix: {}'.format(channel) )
				continue
			log.debug('Joining channel: {}'.format(channel))
			self.proto.join(channel)
	def proto_off(self, irc): self.proto = None

	def proto_msg(self, irc, user, nick, channel, msg):
		if channel not in self.channel_map:
			log.noise( 'Ignoring msg for unmonitored source'
				' (user: {!r}, nick: {!r}, channel: {!r})'.format(user, nick, channel) )
			return
		self.dispatch(msg, source=self.channel_map[channel], user=nick)




	@defer.inlineCallbacks
	def dispatch(self, msg, source, user=None, direct=False):
		if not isinstance(msg, list): msg = [msg]

		channels = dict()
		if direct and user:
			# Direct reply
			log.noise('Dispatching msg from {!r} directly to user: {!r}'.format(source, user))
			channels[user] = msg

		else:
			try: route = self.routes[self.relays.get(source) or source]
			except KeyError:
				log.noise('No routes to dispatch message to, dropping: {!r}'.format(msg))
				return
			# Pull msg through all the pipelines and build dst channels / msgs buffer
			for dst, pipe in route:
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
						extra_kwz = dict()
						if isinstance(dst, types.StringTypes): dst = self.relays[dst]
						if user and 'source' in inspect.getargspec(dst.dispatch).args:
							extra_kwz['source'] = user
						log.noise('Delivering msgs to dst relay: {}, extra_kwz: {}'.format(dst, extra_kwz))
						yield defer.DeferredList(list(
							defer.maybeDeferred(dst.dispatch, msg_copy, **extra_kwz)
							for msg_copy in msg_copy ))
					else:
						channels.setdefault(self.channels[dst].name, set()).update(msg_copy)

		# Check whether anything can be delivered to channels at all
		if not self.proto:
			log.warn( 'Failed to deliver message(s)'
				' ({!r}) to the following channels: {}'.format(msg, channels) )
			defer.returnValue(None)

		# Encode and deliver
		for channel, msg in channels.viewitems():
			for msg in msg:
				if not isinstance(msg, types.StringTypes):
					log.warn('Dropping non-string message: {!r}'.format(msg))
					continue
				if isinstance(msg, unicode):
					try: msg = msg.encode(self.irc_enc)
					except UnicodeEncodeError as err:
						log.warn('Failed to encode ({}) unicode msg ({!r}): {}'.format(self.irc_enc, msg, err))
						msg = msg.encode(self.irc_enc, 'replace')
				max_len = self.proto._safeMaximumLineLength('PRIVMSG {} :'.format(channel)) - 2
				first_line = True
				for line in irc.split(msg, length=max_len):
					if not first_line: line = '  {}'.format(line)
					if not self.dry_run: self.proto.msg(channel, line)
					else: log.info('IRC line (channel: {}): {}'.format(channel, line))
					first_line = False
