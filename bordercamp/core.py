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

	def __init__(self, conf):
		self.conf = conf
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


	def signedOn(self):
		log.debug('Signed on')
		for alias, channel in self.conf.channels.viewitems():
			log.debug('Joining channel: {}'.format(channel.name))
			self.join(channel.name)

	def joined(self, channel): # znc somehow omits these, it seems
		log.debug('Joined channel: {}'.format(channel))


	def privmsg(self, user, channel, message):
		nick = user.split('!', 1)[0]
		if self.conf.nickname_lstrip: nick = nick.lstrip(self.conf.nickname_lstrip)
		log.debug('Got msg: {}'.format([user, nick, channel, message]))

	def action(self, user, channel, message):
		self.privmsg(user, channel, '/me {}'.format(message))

	def noticed(self, user, channel, message):
		self.privmsg(user, channel, '/notice {}'.format(message))



class BCFactory(protocol.ReconnectingClientFactory):

	protocol = property(lambda s: ft.partial(BCBot, s.conf))

	def __init__(self, conf):
		self.conf = conf
		for k,v in self.conf.connection.reconnect.viewitems(): setattr(self, k, v)



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
			' can be specified multiple times. Overrides --collector-enable.')

	parser.add_argument('-c', '--config',
		action='append', metavar='path', default=list(),
		help='Configuration files to process.'
			' Can be specified more than once.'
			' Values from the latter ones override values in the former.'
			' Available CLI options override the values in any config.')

	parser.add_argument('-n', '--dry-run',
		action='store_true', help='Do not connect to IRC, just init all the plugins and exit.')
	parser.add_argument('--debug',
		action='store_true', help='Verbose operation mode.')
	parser.add_argument('--noise',
		action='store_true', help='Even more verbose mode than --debug.')
	optz = parser.parse_args()

	# Read configuration files
	cfg = config.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	# Logging
	import logging
	logging.NOISE = logging.DEBUG - 1
	logging.addLevelName(logging.NOISE, 'NOISE')
	if optz.noise: lvl = logging.NOISE
	elif optz.debug: lvl = logging.DEBUG
	else: lvl = logging.WARNING
	config.configure_logging(cfg.logging, lvl)
	log.PythonLoggingObserver().start()

	for lvl in 'noise', 'debug', 'info', ('warning', 'warn'), 'error':
		lvl, func = lvl if isinstance(lvl, tuple) else (lvl, lvl)
		assert not getattr(log, lvl, False)
		setattr(log, func, ft.partial( log.msg,
			logLevel=logging.getLevelName(lvl.upper()) ))

	# Pluggable components
	relays = config.ep_load(
		'bordercamp', lambda ep_type: ep_type.rstrip('s'),
		config.ep_config( cfg,
			[dict( ep='relays',
				enabled=optz.relay_enable, disabled=optz.relay_disable )] ),
		log=log )
	raise NotImplementedError(relays)

	endpoints\
		.clientFromString(reactor, cfg.core.connection.endpoint)\
		.connect(BCFactory(cfg.core))

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
