#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from datetime import datetime
import os, sys

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
		for alias, channel in self.conf.channels.viewitems():
			log.debug('Joining channel: {}'.format(channel.name))
			self.join(channel.name)
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

	def __init__(self, conf, dry_run=False):
		self.conf, self.dry_run = conf, dry_run

	def proto_on(self, irc): self.proto = irc
	def proto_off(self, irc): self.proto = None
	def proto_msg(self, irc, user, nick, channel, message): pass

	def relay_msg(self, relay, channel, msg):
		if not self.proto: return # TODO: queue
		if isinstance(msg, unicode):
			try: msg = msg.encode(irc_enc)
			except UnicodeEncodeError as err:
				log.warn('Failed to encode ({}) unicode msg ({!r}): {}'.format(irc_enc, msg, err))
				msg = msg.encode(irc_enc, 'replace')
		max_len = self.proto._safeMaximumLineLength('PRIVMSG {} :'.format(channel)) - 2
		first_line, channel = True, self.conf[channel]
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

	# Read configuration files
	cfg = config.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	# CLI overrides
	if optz.dry_run: cfg.debug.dry_run = optz.dry_run

	# Logging
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

	# Fake "xattr" module, if requested
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

	# Actual init
	interface = BCInterface(cfg.core.channels, dry_run=cfg.debug.dry_run)
	relays = config.ep_load(
		'bordercamp', lambda ep_type: ep_type.rstrip('s'),
		config.ep_config( cfg,
			[dict( ep='relays', init_kwz=dict(interface=interface),
				enabled=optz.relay_enable, disabled=optz.relay_disable )] ),
		log=log )
	endpoints\
		.clientFromString(reactor, cfg.core.connection.endpoint)\
		.connect(BCFactory(cfg.core, interface))

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
