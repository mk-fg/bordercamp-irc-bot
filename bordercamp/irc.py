# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from datetime import datetime
import os, sys

from twisted.internet import reactor, protocol, defer
from twisted.words.service import IRCUser, IRCFactory, InMemoryWordsRealm
from twisted.cred import checkers, credentials, portal
from twisted.words.protocols import irc
from twisted.python import log


class BCBot(irc.IRCClient):

	versionName, versionEnv = 'bordercamp', '{1} ({0})'.format(*os.uname()[:2])
	versionNum = '.'.join( bytes(int(num)) for num in
		datetime.fromtimestamp(os.stat(__file__).st_mtime).strftime('%y %m %d').split() )
	sourceURL = 'http://github.com/mk-fg/bordercamp-irc-bot'

	def __init__(self, conf, interface):
		self.conf, self.interface = conf, interface
		self.heartbeatInterval = self.conf.connection.heartbeat
		for k in 'nickname', 'realname',\
				'username', 'password', 'userinfo', 'nickname':
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
		log.noise('Got msg: {}'.format([user, nick, channel, message]))
		self.interface.proto_msg(self, user, nick, channel, message)

	def action(self, user, channel, message):
		self.privmsg(user, channel, '/me {}'.format(message))

	def noticed(self, user, channel, message):
		self.privmsg(user, channel, '/notice {}'.format(message))



class BCClientFactory(protocol.ReconnectingClientFactory):

	protocol = property(lambda s: ft.partial(BCBot, s.conf, s.interface))

	def __init__(self, conf, interface, ep):
		self.conf, self.interface, self.ep = conf, interface, ep
		for k,v in self.conf.connection.reconnect.viewitems(): setattr(self, k, v)

	def connect(self):
		self.ep.connect(self)

	def doStop(self):
		protocol.ReconnectingClientFactory.doStop(self)
		if self.continueTrying:
			self.connector = self
			self.retry()


class BCIRCUser(IRCUser):

	_welcomeMessages = IRCUser._welcomeMessages + [
		(irc.RPL_ISUPPORT, 'NETWORK=%(serviceName)s :are supported by this server') ]

	_motd = None
	@property
	def _motdMessages(self):
		if self._motd is None:
			self._motd =\
				[(irc.RPL_MOTDSTART, ":- %(serviceName)s Message of the Day - ")]\
				+ list((irc.RPL_MOTD, ': {}'.format(line.strip())) for line in self.factory.motd)\
				+ [(irc.RPL_ENDOFMOTD, ":End of /MOTD command.")]
		return self._motd

	def irc_unknown(self, prefix, command, params):
		log.info('Ignoring unhandled irc command: {!r}'.format([prefix, command, params]))
		if self.nickname:
			self.sendMessage( irc.ERR_UNKNOWNCOMMAND,
				':Unknown command ({!r}, parameters: {!r})'.format(command, params) )

	def irc_CAP(self, prefix, params): pass # no support for caps
	def irc_AWAY(self, prefix, params): pass # no point in these

	def irc_MOTD(self, prefix=None, params=None):
		for code, text in self._motdMessages:
			self.sendMessage(code, text % self.factory._serverInfo)

	def irc_JOIN(self, prefix, params):
		for channel in (params[0].split(',') if ',' in params[0] else [params[0]]):
			IRCUser.irc_JOIN(self, prefix, [channel] + params[1:])

	def irc_NICK(self, prefix, params):
		try: nickname = params[0].decode(self.encoding)
		except UnicodeDecodeError:
			self.privmsg( NICKSERV, nickname,
				'Nickname cannot be decoded. Use ASCII or {}.'.format(self.encoding.upper()) )
			self.transport.loseConnection()
			return

		self.nickname = self.name = nickname
		self.irc_MOTD()

		if self.password is not None:
			password, self.password = self.password, None
			self.logInAs(nickname, password)


class BCServerFactory(IRCFactory):

	protocol = BCIRCUser
	motd = list()

	def __init__(self, conf, *channels, **extra_creds):
		self.conf = conf

		realm = InMemoryWordsRealm(self.conf.name)
		passwd = (self.conf.passwd or dict()).copy()
		passwd.update(extra_creds)
		realm_portal = portal.Portal(realm, [
			checkers.InMemoryUsernamePasswordDatabaseDontUse(**passwd) ])
		for channel in channels:
			if channel[0] == '#': channel = channel[1:]
			realm.createGroup(unicode(channel))

		IRCFactory.__init__(self, realm, realm_portal)
		if self.conf.motd: self.motd = self.conf.motd.splitlines()
