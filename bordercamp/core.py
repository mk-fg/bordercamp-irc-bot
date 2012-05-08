#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from datetime import datetime
import os, sys, pkg_resources

from twisted.internet import reactor, endpoints, protocol, error, task, defer
from twisted.words.protocols import irc
from twisted.python import log

from bordercamp import config


class BCBot(irc.IRCClient):

	versionName, versionEnv = 'bordercamp', '{1} ({0})'.format(*os.uname()[:2])
	versionNum = '.'.join( bytes(int(num)) for num in
		datetime.fromtimestamp(os.stat(__file__).st_mtime).strftime('%y %m %d').split() )
	sourceURL = 'http://github.com/mk-fg/bordercamp-irc-bot'

	def __init__(self, conf, interface):
		self.conf, self.interface = conf, interface
		self.heartbeatInterval = self.conf.connection.heartbeat
		for k in 'realname', 'username', 'password', 'userinfo':
			v = self.conf.connection.get(k)
			if v: setattr(self, k, v)

	def connectionMade(self):
		irc.IRCClient.connectionMade(self)
		log.debug('Connected to IRC server')

	def connectionLost(self, reason):
		log.debug('Lost connection to the IRC server: {}'.format(reason))
		irc.IRCClient.connectionLost(self, reason)
		self.interface.proto_off(self)


	def signedOn(self):
		log.debug('Signed on')
		self.interface.proto_on(self)

	def joined(self, channel): # znc somehow omits these, it seems
		log.debug('Joined channel: {}'.format(channel))


	def privmsg(self, user, channel, message):
		nick = user.split('!', 1)[0]
		if self.conf.nickname_lstrip: nick = nick.lstrip(self.conf.nickname_lstrip)
		log.debug('Got msg: {}'.format([user, nick, channel, message]))
		self.interface.proto_msg(self, user, nick, channel, message)

	def action(self, user, channel, message):
		self.privmsg(user, channel, '/me {}'.format(message))

	def noticed(self, user, channel, message):
		self.privmsg(user, channel, '/notice {}'.format(message))



class BCFactory(protocol.ReconnectingClientFactory):

	protocol = property(lambda s: ft.partial(BCBot, s.conf, s.interface))

	def __init__(self, conf, interface):
		self.conf, self.interface = conf, interface
		for k,v in self.conf.connection.reconnect.viewitems(): setattr(self, k, v)



class BCInterface(object):
	'''Persistent "interface" object sitting in-between persistent relay objects
		and transient protocol objects, queueing/multiplexing messages from
		relays to the protocols and messages/events from protocols to relays.'''
	# TODO: rate control, UDP interface

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

		for name, relay_obj in relays.items():
			relays[relay_obj] = relays[name] = name

		self.relays, self.channels, self.routes = relays, channels, pipes

	def proto_on(self, irc):
		self.proto = irc
		for alias, channel in self.channels.viewitems():
			log.debug('Joining channel: {}'.format(channel.name))
			self.proto.join(channel.name)
	def proto_off(self, irc): self.proto = None

	def proto_msg(self, irc, user, nick, channel, message): pass

	def relay_msg(self, relay, msg):
		relay = self.relays[relay]
		if not self.proto: return # TODO: queue
		if isinstance(msg, unicode):
			try: msg = msg.encode(irc_enc)
			except UnicodeEncodeError as err:
				log.warn('Failed to encode ({}) unicode msg ({!r}): {}'.format(irc_enc, msg, err))
				msg = msg.encode(irc_enc, 'replace')
		for channel in self.channels.viewvalues():
			max_len = self.proto._safeMaximumLineLength('PRIVMSG {} :'.format(channel)) - 2
			first_line = True
			for line in irc.split(msg, length=max_len):
				if not first_line: line = '  {}'.format(line)
				if not self.dry_run: self.proto.msg(channel.name, line)
				else: log.info('IRC line (channel: {}): {}'.format(channel.name, line))
				first_line = False


def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Start the IRC helper bot.')

	parser.add_argument('-e', '--relay-enable',
		action='append', metavar='relay', default=list(),
		help='Enable only the specified relays, can be specified multiple times.')
	parser.add_argument('-d', '--relay-disable',
		action='append', metavar='relay', default=list(),
		help='Explicitly disable specified relays,'
			' can be specified multiple times. Overrides --relay-enable.')

	parser.add_argument('-c', '--config',
		action='append', metavar='path', default=list(),
		help='Configuration files to process.'
			' Can be specified more than once.'
			' Values from the latter ones override values in the former.'
			' Available CLI options override the values in any config.')

	parser.add_argument('-n', '--dry-run', action='store_true',
		help='Connect to IRC, but do not communicate there,'
			' dumping lines-to-be-sent to the log instead.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--noise',
		action='store_true', help='Even more verbose mode than --debug.')
	optz = parser.parse_args()

	## Read configuration files
	cfg = config.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	## CLI overrides
	if optz.dry_run: cfg.debug.dry_run = optz.dry_run

	## Logging
	import logging
	logging.NOISE = logging.DEBUG - 1
	logging.addLevelName(logging.NOISE, 'NOISE')
	if optz.noise: lvl = logging.NOISE
	elif optz.debug: lvl = logging.DEBUG
	else: lvl = logging.WARNING
	config.configure_logging(cfg.logging, lvl)
	log.PythonLoggingObserver().start()

	for lvl in 'noise', 'debug', 'info', ('warning', 'warn'), 'error', ('critical', 'fatal'):
		lvl, func = lvl if isinstance(lvl, tuple) else (lvl, lvl)
		assert not getattr(log, lvl, False)
		setattr(log, func, ft.partial( log.msg,
			logLevel=logging.getLevelName(lvl.upper()) ))

	## Fake "xattr" module, if requested
	if cfg.core.xattr_emulation:
		import shelve
		xattr_db = shelve.open(cfg.core.xattr_emulation, 'c')
		class xattr_path(object):
			def __init__(self, base):
				assert isinstance(base, bytes)
				self.base = base
			def key(self, k): return '{}\0{}'.format(self.base, k)
			def __setitem__(self, k, v): xattr_db[self.key(k)] = v
			def __getitem__(self, k): return xattr_db[self.key(k)]
			def __del__(self): xattr_db.sync()
		class xattr_module(object): xattr = xattr_path
		sys.modules['xattr'] = xattr_module

	## Actual init
	# Merge entry points configuration with CLI opts
	conf = config.ep_config( cfg,
		[dict( ep='modules',
			enabled=optz.relay_enable, disabled=optz.relay_disable )] )
	conf_base, conf = conf['modules']
	for subconf in conf.viewvalues(): subconf.rebase(conf_base)
	relays, channels, routes = (
		dict( (name, subconf) for name,subconf in conf.viewitems()
		if name[0] != '_' and subconf.get('type') == subtype )
		for subtype in ['relay', 'channel', 'route'] )

	# Init interface
	interface = BCInterface(dry_run=cfg.debug.dry_run)

	# Init relays
	relays_valid = set()
	for ep in pkg_resources.iter_entry_points('bordercamp.relays'):
		if ep.name[0] == '_':
			log.debug( 'Skipping entry_point with name'
				' prefixed by underscore: {}'.format(ep.name) )
			continue
		ep_relays = list( (name, subconf)
			for name, subconf in relays.viewitems()
			if subconf.get('name', name) == ep.name )
		if not ep_relays: ep_relays = [(ep.name, conf_base.clone())]
		for name, subconf in ep_relays:
			if subconf.get('enabled', True):
				log.debug('Loading relay: {}'.format(ep.name))
				try:
					obj = ep.load().relay(subconf, interface=interface)
					if not obj: raise AssertionError('Empty object')
				except Exception as err:
					log.error('Failed to load/init relay {}: {}'.format(ep.name, err))
					obj, subconf.enabled = None, False
			if obj and subconf.get('enabled', True):
				relays[name] = obj
				relays_valid.add(name)
			else:
				log.debug(( 'Entry point object {!r} (name:'
					' {}) was disabled after init' ).format(obj, ep.name) )
	for name in set(relays).difference(relays_valid):
		log.debug(( 'Unused relay configuration - {}: no such'
			' entry point - {}' ).format(name, relays[name].get('name', name)))
		del relays[name]
	if not relays:
		log.fatal('No relay objects were properly enabled/loaded, bailing out')
		sys.exit(1)
	log.debug('Enabled relays: {}'.format(relays))

	interface.update(relays, channels, routes)
	endpoints\
		.clientFromString(reactor, cfg.core.connection.endpoint)\
		.connect(BCFactory(cfg.core, interface))

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
