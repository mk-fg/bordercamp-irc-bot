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
		for sub, func in [
				('addr', lambda addr: socket.gethostbyaddr(addr)[0]),
				('host', lambda host: socket.gethostbyname_ex(host)[2][0]) ]:
			try: group = match.group(sub)
			except IndexError: continue
			try: group = func(group)
			except (socket.herror, IndexError) as err:
				log.debug('Failed to resolve {} ({}): {}'.format(sub, group, err))
			else:
				if sub == 'addr' and self.conf.get('short', False): group = group.split('.', 1)[0]
			return msg[:match.start(sub)] + group + msg[match.end(sub):]


relay = Resolver
