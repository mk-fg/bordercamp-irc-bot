# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import re

from twisted.python import log

from . import BCRelay


class Shortener(BCRelay):

	def __init__(self, *argz, **kwz):
		super(Shortener, self).__init__(*argz, **kwz)
		log.noise('Compiling regex: {!r}'.format(self.conf.regex))
		self.regex = re.compile(self.conf.regex)

	def dispatch(self, msg):
		match = self.regex.search(msg)
		if not match: return msg
		return msg[:match.start('url')]\
			+ self.shorten(match.group('url'))\
			+ msg[match.end('url'):]


	def shorten(self, url):
		try: func = getattr(self, 'shorten_{}'.format(self.conf.api.type))
		except AttributeError:
			raise ValueError('URL shortener "{}" is not supported')
		return func(url, self.conf.api.parameters)


	def shorten_cut(self, url, params):
		return url[:params]


relay = Shortener
