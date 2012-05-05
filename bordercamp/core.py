#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import unicode_literals, print_function
import itertools as it, operator as op, functools as ft


import os, sys
sys.path.insert(0, os.path.dirname(
	os.path.dirname(os.path.realpath(__file__)) ))
from django.core.management import setup_environ
import settings
setup_environ(settings)



from ves.forager import settings as cfg
from time import time, localtime, strftime

class IrcLoggerBackend(object):
	filename_tpl = stream = None
	flow, flow_check = 0, 16384 # log traffic between size checks

	def __init__(self, source, sync=cfg.irc_log_sync is True):
		self.filename_tpl = cfg.irc_log_name.format(source=source, timestamp='{0}')

	def send(self, message):
		ts = int(time())
		if self.flow > self.flow_check:
			try:
				if os.stat(self.stream.name).st_size > cfg.irc_log_max_size: self.stream.close()
			except (OSError, IOError): self.stream = None
			self.flow = 0
		if not self.stream or self.stream.closed:
			self.stream = open(self.filename_tpl.format(ts), 'a')
		message = '{0} {1} {2}\n'.format( ts,
				strftime(cfg.irc_log_ts_hr, localtime(ts)), message.strip() )\
			.encode(cfg.irc_enc, 'backslashreplace')
		self.flow += len(message) # in bytes
		self.stream.write(message)
		if cfg.irc_log_sync: self.stream.flush()

	def sync(self):
		if self.stream and not self.stream.closed: self.stream.flush()

	def __del__(self):
		try: self.stream.close()
		except: pass



from twisted.words.protocols import irc
from twisted.internet import reactor, protocol, task, error

from string import maketrans, whitespace
from django.utils.encoding import smart_unicode
smart_unicode = ft.partial(smart_unicode, encoding=cfg.irc_enc, errors='replace')


class IrcLogger(irc.IRCClient):

	logger_sys = None # connection log
	loggers = loggers_sync_timer = None
	user_trans = maketrans(whitespace, b'_'*len(whitespace)) # there will be no whitespace
	nickname = property(lambda s: str(s.factory.nick)) # used by twisted, unicode is not allowed


	def connectionMade(self, syslog=None):
		irc.IRCClient.connectionMade(self)
		self.logger_sys = getattr(self.factory, 'logger_sys', None) or\
			IrcLoggerBackend(source=self.factory.servername)
		self.logger_sys.send('-- Connected')
		self.loggers = dict()
		self.heartbeat_timer = task.LoopingCall(self.heartbeat)
		if isinstance(cfg.irc_log_sync, int) and cfg.irc_log_sync > 0:
			self.loggers_sync_timer = task.LoopingCall(self.loggers_sync)
			self.loggers_sync_timer\
				.start(cfg.irc_log_sync, now=False)\
				.addCallback(lambda res: self.loggers_sync()) # sync on stop

	def connectionLost(self, reason):
		self.heartbeat_timer.stop()
		irc.IRCClient.connectionLost(self, reason)
		self.logger_sys.send('-- Disconnected (reason: {0})'.format(smart_unicode(reason)))
		if self.loggers_sync_timer: self.loggers_sync_timer.stop()

	def loggers_sync(self):
		if self.logger_sys: self.logger_sys.sync()
		if self.loggers:
			for logger in self.loggers.itervalues(): logger.sync()


	def heartbeat(self):
		if self.connected:
			if hasattr(self, 'heartbeat_sync'):
				try: self.heartbeat_sync.cancel()
				except (error.AlreadyCalled, error.AlreadyCancelled): pass
			self.ping(bytes(cfg.irc_heartbeat_scapegoat))
			self.heartbeat_sync = reactor.callLater(
				cfg.irc_heartbeat_wait, self.heartbeat_fail )

	def heartbeat_fail(self):
		self.logger_sys.send('-- Heartbeat failure, resetting the link')
		self.quit(b'sh** happened')

	def pong(self, user, secs):
		try: self.heartbeat_sync.cancel()
		except (error.AlreadyCalled, error.AlreadyCancelled):
			self.logger_sys.send('Unsynced heartbeat pong detected')


	def signedOn(self):
		self.heartbeat_timer.start(cfg.irc_heartbeat_interval, now=False)
		for channel in self.factory.channels: self.join(channel)

	def joined(self, channel):
		self.loggers[channel] = IrcLoggerBackend(
			source=cfg.irc_log_source.format(server=self.factory.servername, channel=channel) )
		self.logger_sys.send('Joined channel: {0}'.format(channel))


	def msg(self, nick, msg, *argz, **kwz):
		if isinstance(nick, unicode): nick = nick.encode(cfg.irc_enc)
		if isinstance(msg, unicode): msg = msg.encode(cfg.irc_enc)
		return irc.IRCClient.msg(self, nick, msg, *argz, **kwz)


	def privmsg(self, user, channel, message, sys=False):
		user, channel, message = it.imap( smart_unicode,
			(user.translate(self.user_trans), channel, message) )
		nick = user.split('!', 1)[0]
		if not sys:
			try:
				self.loggers[channel].send('{0} ({1}) {2}'.format(nick, user, message))
				self.factory.activity_callback() # indication that it's Still Alive
			except KeyError: sys = True
		if sys: # can be used as a fallback
			self.logger_sys.send( 'Off-the-record'
				' (channel: {0}, user: {1}): {2}'.format(channel, user, message) )

	def action(self, user, channel, message):
		self.privmsg(user, channel, '/me {0}'.format(smart_unicode(message)))

	def noticed(self, user, channel, message):
		self.privmsg(user, channel, '/notice {0}'.format(smart_unicode(message)))

	def kickedFrom(self, channel, user, message):
		self.privmsg( user, channel,
			'KICKED - {0!r}'.format(smart_unicode(message)), sys=True )



class IrcLoggerFactory(protocol.ClientFactory):

	protocol = IrcLogger
	channels = tuple()
	nick = servername = None
	logger_sys = None
	_attempts = 0


	def __init__(self, channels, nick, servername='generic'):
		channels = map(str, channels) # twisted irc client is unable to handle unicode here
		self.channels, self.nick, self.servername = channels, nick, servername
		self.logger_sys = IrcLoggerBackend(source=self.servername)
		self._attempts = cfg.irc_reconnect_tries


	def activity_callback(self):
		self._attempts = cfg.irc_reconnect_tries

	def recover_after_failure(self, connector):
		if self._attempts <= 0:
			self.logger_sys.send('Too many connection failures in a row, breaking up')
			reactor.stop()
		self._attempts -= 1
		reactor.callLater(cfg.irc_reconnect, connector.connect)
		self.logger_sys.send(( '-- waiting for {0} seconds before'
			' reconnection attempt' ).format(cfg.irc_reconnect))


	def clientConnectionLost(self, connector, reason):
		self.recover_after_failure(connector)

	def clientConnectionFailed(self, connector, reason):
		self.logger_sys.send('-- Connection failed (reason: {0})'.format(smart_unicode(reason)))
		self.recover_after_failure(connector)




if __name__ == '__main__':
	from optparse import OptionParser
	parser = OptionParser(usage='%prog',
		description='Log IRC channels, specified in the configuration.')
	optz, argz = parser.parse_args()
	if argz: parser.error('This command takes no arguments.')
	for source, ((host, port), channels) in cfg.irc_sources.iteritems():
		reactor.connectTCP( host, port,
			IrcLoggerFactory(channels, cfg.irc_bot_nick, source) )
	reactor.run()
