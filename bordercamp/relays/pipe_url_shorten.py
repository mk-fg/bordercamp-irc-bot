# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.internet import defer
from twisted.python import log

from bordercamp.http import HTTPClient
from bordercamp import force_bytes
from . import BCRelay

import itertools as it, operator as op, functools as ft
import os, re


class Shortener(BCRelay):

	def __init__(self, *argz, **kwz):
		super(Shortener, self).__init__(*argz, **kwz)
		log.noise('Compiling regex: {!r}'.format(self.conf.regex))
		self.regex = re.compile(self.conf.regex)
		self.client = HTTPClient()

	@defer.inlineCallbacks
	def dispatch(self, msg):
		match = self.regex.search(msg)
		if not match: defer.returnValue(msg)
		defer.returnValue(( msg[:match.start('url')]\
			+ (yield self.shorten(match.group('url'))) + msg[match.end('url'):] ))


	@defer.inlineCallbacks
	def shorten(self, url):
		if len(url) >= self.conf.length_min:
			try: func = getattr(self, 'shorten_{}'.format(self.conf.api.type))
			except AttributeError:
				raise ValueError('URL shortener "{}" is not supported')
			url = yield defer.maybeDeferred(func, url, self.conf.api.parameters)
		defer.returnValue(re.sub(r'^(?i)(https?|spdy)://', '', url))


	def shorten_cut(self, url, params):
		return url[:(params or 50)]

	@defer.inlineCallbacks
	def shorten_m29(self, url, params):
		# based on https://github.com/netd/m29_python
		import Crypto.Cipher.AES # pycrypto

		key1, key2 = os.urandom(8), os.urandom(8)
		pad = lambda s: s + (16 - len(s) % 16) * '\0'
		encrypted = Crypto.Cipher.AES\
			.new(key1 + key2, Crypto.Cipher.AES.MODE_ECB)\
			.encrypt(pad(url))

		base64 = lambda url: url.encode('base64')\
			.strip().replace('+', '-').replace('/', '_').replace('=', '')
		data, headers = yield self.client.request(
			'http://api.m29.us/urlshortener/v1/url',
			'post', encode='json', decode='json',
			data=dict( firstKey=base64(key1),
				longUrlEncrypted=base64(encrypted) ) )
		defer.returnValue(data['id'] + '/' + base64(key2))


relay = Shortener
