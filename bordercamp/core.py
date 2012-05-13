#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys, pkg_resources

from twisted.internet import reactor, endpoints, protocol, defer
from twisted.python import log

from bordercamp import config, irc, routing


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
	interface = routing.BCInterface(dry_run=cfg.debug.dry_run)

	# Init relays
	relays_obj = dict()
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
				log.debug('Loading relay: {} ({})'.format(name, ep.name))
				try: relay_defaults = cfg.relay_defaults[ep.name]
				except KeyError: pass
				else: subconf.rebase(relay_defaults)
				try:
					obj = ep.load().relay(subconf, interface=interface)
					if not obj: raise AssertionError('Empty object')
				except Exception as err:
					log.error('Failed to load/init relay {}: {}'.format(ep.name, err))
					obj, subconf.enabled = None, False
			if obj and subconf.get('enabled', True): relays_obj[name] = obj
			else:
				log.debug(( 'Entry point object {!r} (name:'
					' {}) was disabled after init' ).format(obj, ep.name) )
	for name in set(relays).difference(relays_obj):
		log.debug(( 'Unused relay configuration - {}: no such'
			' entry point - {}' ).format(name, relays[name].get('name', name)))
	if not relays_obj:
		log.fatal('No relay objects were properly enabled/loaded, bailing out')
		sys.exit(1)
	log.debug('Enabled relays: {}'.format(relays_obj))

	# Relays-client interface
	interface.update(relays_obj, channels, routes)

	# Server
	if cfg.core.connection.server.endpoint:
		password = cfg.core.connection.get('password')
		if not password:
			from hashlib import sha1
			password = cfg.core.connection.password =\
				sha1(open('/dev/urandom', 'rb').read(120/8)).hexdigest()
		factory = irc.BCServerFactory(
			cfg.core.connection.server,
			*(chan.get('name', name) for name,chan in channels.viewitems()),
			**{cfg.core.connection.nickname: password} )
		endpoints\
			.serverFromString(reactor, cfg.core.connection.server.endpoint)\
			.listen(factory)

	# Client
	endpoints\
		.clientFromString(reactor, cfg.core.connection.endpoint)\
		.connect(irc.BCClientFactory(cfg.core, interface))

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
