# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import re, socket

from twisted.python import log

from . import BCRelay


class Resolver(BCRelay):

	def __init__(self, *argz, **kwz):
		super(Resolver, self).__init__(*argz, **kwz)
		log.noise('Compiling regex: {!r}'.format(self.conf.addr))
		self.regex = re.compile(self.conf.addr)

	def dispatch(self, msg):
		match = self.regex.search(msg)
		if not match:
			log.debug('Failed to match address, msg: {!r}'.format(msg))
			return msg
		addr = match.group('addr')
		try: addr = socket.gethostbyaddr(addr)[0]
		except socket.herror as err:
			log.debug('Failed to resolve address to hostname ({}): {}'.format(addr, err))
		else:
			if self.conf.get('short', False): addr = addr.split('.', 1)[0]
		return msg[:match.start('addr')] + addr + msg[match.end('addr'):]


relay = Resolver
