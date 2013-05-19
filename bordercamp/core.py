#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from os.path import join, dirname, isdir, exists, splitext, realpath
import os, sys, pkg_resources

from twisted.internet import reactor, endpoints, protocol, defer
from twisted.python import log

import lya


try: from bordercamp import irc, routing
except ImportError:
	# Make sure it works from a checkout
	if isdir(join(dirname(__file__), 'bordercamp'))\
			and exists(join(dirname(__file__), 'setup.py')):
		sys.path.insert(0, dirname(__file__))
	from bordercamp import irc, routing


def ep_config(cfg, ep_specs):
	# ep_specs = [{ ep='relays',
	#  enabled=[ep_name, ...], disabled=[ep_name, ...] }, ...]
	ep_conf = dict()
	for spec in ep_specs:
		ep = spec['ep']
		conf = cfg.get(ep) or lya.AttrDict()
		conf_base = conf.pop('_default')
		enabled = spec.get('enabled', list())
		if enabled:
			for name, subconf in conf.viewitems():
				if name not in enabled: subconf['enabled'] = False
			for name in enabled:
				if name not in conf: conf[name] = dict()
				conf[name]['enabled'] = True
		disabled = spec.get('disabled', list())
		for name in disabled:
			if name not in conf: conf[name] = dict()
			conf[name]['enabled'] = False
		if 'debug' not in conf_base: conf_base['debug'] = cfg.debug
		ep_conf[ep] = conf_base, conf
	return ep_conf


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
	parser.add_argument('--fatal-errors', action='store_true',
		help='Do not try to ignore entry_point'
			' init errors, bailing out with traceback instead.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--noise',
		action='store_true', help='Even more verbose mode than --debug.')
	optz = parser.parse_args()

	## Read configuration files
	cfg = lya.AttrDict.from_yaml('{}.yaml'.format(splitext(realpath(__file__))[0]))
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
	lya.configure_logging(cfg.logging, lvl)
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
				assert isinstance(base, str)
				self.base = base
			def key(self, k): return '{}\0{}'.format(self.base, k)
			def __setitem__(self, k, v): xattr_db[self.key(k)] = v
			def __getitem__(self, k): return xattr_db[self.key(k)]
			def __del__(self): xattr_db.sync()
		class xattr_module(object): xattr = xattr_path
		sys.modules['xattr'] = xattr_module

	## Actual init
	# Merge entry points configuration with CLI opts
	conf = ep_config( cfg,
		[ dict(ep='relay_defaults'),
			dict( ep='modules',
				enabled=optz.relay_enable, disabled=optz.relay_disable ) ] )
	(conf_base, conf), (conf_def_base, conf_def) =\
		op.itemgetter('modules', 'relay_defaults')(conf)
	for subconf in conf.viewvalues(): subconf.rebase(conf_base)
	relays, channels, routes = (
		dict( (name, subconf) for name,subconf in conf.viewitems()
		if name[0] != '_' and subconf.get('type') == subtype )
		for subtype in ['relay', 'channel', 'route'] )

	# Init interface
	interface = routing.BCInterface( irc_enc=cfg.core.encoding,
		chan_prefix=cfg.core.channel_prefix, dry_run=cfg.debug.dry_run )

	# Find out which relay entry_points are actually used
	route_mods = set(it.chain.from_iterable(
		it.chain.from_iterable(
			(mod if isinstance(mod, list) else [mod])
			for mod in ((route.get(k) or list()) for k in ['src', 'dst', 'pipe']) )
		for route in routes.viewvalues() ))
	for name in list(route_mods):
		try:
			name_ep = relays[name].name
			if name == name_ep: continue
		except KeyError: pass
		else:
			route_mods.add(name_ep)
			route_mods.remove(name)

	# Init relays
	relays_obj = dict()
	for ep in pkg_resources.iter_entry_points('bordercamp.relays'):
		if ep.name[0] == '_':
			log.debug( 'Skipping entry_point with name'
				' prefixed by underscore: {}'.format(ep.name) )
			continue
		if ep.name not in route_mods:
			log.debug(( 'Skipping loading relay entry_point {}'
				' because its not used in any of the routes' ).format(ep.name))
			continue
		ep_relays = list( (name, subconf)
			for name, subconf in relays.viewitems()
			if subconf.get('name', name) == ep.name )
		if not ep_relays: ep_relays = [(ep.name, conf_base.clone())]
		for name, subconf in ep_relays:
			try: relay_defaults = conf_def[ep.name]
			except KeyError: pass
			else:
				subconf.rebase(relay_defaults)
				subconf.rebase(conf_def_base)
			if subconf.get('enabled', True):
				log.debug('Loading relay: {} ({})'.format(name, ep.name))
				try:
					obj = ep.load().relay(subconf, interface=interface)
					if not obj: raise AssertionError('Empty object')
				except Exception as err:
					if optz.fatal_errors: raise
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

	# Client with proper endpoints + reconnection
	# See: http://twistedmatrix.com/trac/ticket/4472 + 4700 + 4735
	ep = endpoints.clientFromString(reactor, cfg.core.connection.endpoint)
	irc.BCClientFactory(cfg.core, interface, ep).connect()

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
