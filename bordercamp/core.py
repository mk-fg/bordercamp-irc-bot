#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import os, sys

from twisted.internet import reactor, protocol, error, task, defer
from twisted.words.protocols import irc
from twisted.python import log

from bordercamp import config


class BCBot(irc.IRCClient):

	nickname = property(lambda s: s.factory.conf.connection.nick) # used by twisted
	realname = 'bordercamp bot'
	heartbeatInterval = property(lambda s: s.factory.conf.connection.heartbeat)

	def __init__(self, conf):
		self.conf = conf

	def connectionMade(self):
		irc.IRCClient.connectionMade(self)
		log.debug('Connected to IRC server')

	def connectionLost(self, reason):
		log.debug('Lost connection to the IRC server: {}'.format(reason))
		irc.IRCClient.connectionLost(self, reason)


	def signedOn(self):
		for alias, channel in self.conf.channels.viewitems():
			self.join(channel.name)

	def joined(self, channel):
		log.debug('Joined channel: {}'.format(channel))


	# def privmsg(self, user, channel, message, sys=False):
	# 	nick = user.split('!', 1)[0]
	# 	if not sys:
	# 		try:
	# 			self.loggers[channel].send('{0} ({1}) {2}'.format(nick, user, message))
	# 			self.factory.activity_callback() # indication that it's Still Alive
	# 		except KeyError: sys = True
	# 	if sys: # can be used as a fallback
	# 		self.logger_sys.send( 'Off-the-record'
	# 			' (channel: {0}, user: {1}): {2}'.format(channel, user, message) )

	def action(self, user, channel, message):
		self.privmsg(user, channel, '/me {}'.format(message))

	def noticed(self, user, channel, message):
		self.privmsg(user, channel, '/notice {}'.format(message))

	# def kickedFrom(self, channel, user, message):
	# 	self.privmsg( user, channel,
	# 		'KICKED - {0!r}'.format(smart_unicode(message)), sys=True )



class BCFactory(protocol.ReconnectingClientFactory):

	protocol = property(lambda s: ft.partial(BCBot, s.conf))

	def __init__(self, conf):
		self.conf = conf
		for k,v in self.conf.connection.reconnect.viewitems(): setattr(self, k, v)



def main():
	import argparse
	parser = argparse.ArgumentParser(
		description='Start the IRC helper bot.')

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
	optz = parser.parse_args()

	# Read configuration files
	cfg = config.AttrDict.from_yaml('{}.yaml'.format(
		os.path.splitext(os.path.realpath(__file__))[0] ))
	for k in optz.config: cfg.update_yaml(k)

	# Logging
	import logging
	config.configure_logging( cfg.logging,
		logging.DEBUG if optz.debug else logging.WARNING )
	log.PythonLoggingObserver().start()

	for lvl in 'noise', 'debug', 'info', ('warning', 'warn'), 'error':
		lvl, func = lvl if isinstance(lvl, tuple) else (lvl, lvl)
		assert not getattr(log, lvl, False)
		setattr(log, func, ft.partial( log.msg,
			logLevel=logging.getLevelName(lvl.upper()) ))

	# Init pluggable components
	# import pkg_resources
	# relays = dict( (ep.name, ep.load()) for ep in
	# 	pkg_resources.iter_entry_points('bordercamp.relays') )
	# raise NotImplementedError(repr(relays))

	reactor.connectTCP( cfg.core.connection.host,
		cfg.core.connection.port, BCFactory(cfg.core) )

	log.debug('Starting event loop')
	reactor.run()

if __name__ == '__main__': main()
