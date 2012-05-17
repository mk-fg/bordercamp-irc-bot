# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from logging.handlers import BufferingHandler
from collections import deque
import logging, signal

from twisted.internet import reactor, protocol, defer
from twisted.python import log

from . import BCRelay


class DebugDumper(BCRelay):

	def __init__(self, *argz, **kwz):
		super(DebugDumper, self).__init__(*argz, **kwz)

		# Simple buffered handler that never triggers flush
		self.handler = BufferingHandler(capacity=self.conf.capacity)
		self.buffer = self.handler.buffer = deque(maxlen=self.handler.capacity)
		self.handler.capacity += 1
		self.handler.setLevel(self.conf.level)
		self.handler.setFormatter(
			logging.Formatter(self.conf.format, self.conf.datefmt) )
		logging.root.addHandler(self.handler)

		# Signal log-dump interface
		if self.conf.signal and isinstance(self.conf.signal, str):
			signum = getattr(signal, self.conf.signal, None)
			if not signum: signum = getattr(signal, 'SIG{}'.format(self.conf.signal), None)
			self.conf.signal = signum
		if self.conf.signal:
			def signal_handler(sig, frm):
				# Supress buffering of re-issued messages
				self.handler._emit, self.handler.emit = self.handler.emit, lambda *a, **k: None
				for msg in list(self.buffer): log.fatal(self.handler.format(msg))
				self.handler.emit = self.handler._emit
			signal.signal(self.conf.signal, signal_handler)

	def dispatch(self, msg, source=None):
		if msg != self.conf.command:
			log.noise('Ignoring unknown command: {!r} (source: {})'.format(msg, source))
			return
		if not self.conf.direct: source = None # reply to whatever destination channel
		msg = '\n'.join(it.imap(self.handler.format, list(self.buffer)))
		reactor.callLater( 0, self.interface.dispatch,
			msg, source=self, user=source, direct=True )


relay = DebugDumper
