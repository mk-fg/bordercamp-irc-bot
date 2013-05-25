# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp import force_bytes
from . import BCRelay

import itertools as it, operator as op, functools as ft
import re


## https://github.com/netd/m29_python

import os, json, httplib # would be great to replace w/ twisted.web.client

def get_m29_url(url):
	import Crypto.Cipher.AES # pycrypto

	key1, key2 = os.urandom(8), os.urandom(8)
	pad = lambda s: s + (16 - len(s) % 16) * '\0'
	encrypted = Crypto.Cipher.AES\
		.new(key1 + key2, Crypto.Cipher.AES.MODE_ECB)\
		.encrypt(pad(force_bytes(url)))

	base64 = lambda url: url.encode('base64')\
		.strip().replace('+', '-').replace('/', '_').replace('=', '')

	data = json.dumps(dict(
		longUrlEncrypted=base64(encrypted),
		firstKey=base64(key1) ), ensure_ascii=False)
	conn = httplib.HTTPConnection('api.m29.us', 80)
	try:
		conn.request( 'POST', '/urlshortener/v1/url',
			data, {'Content-Type': 'application/json'} )
		response = conn.getresponse()
		if response.status != 200: return 'error'
		data = response.read()
	finally: conn.close()

	data = json.loads(data)
	return data['id'] + '/' + base64(key2)


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
		if len(url) >= self.conf.length_min:
			try: func = getattr(self, 'shorten_{}'.format(self.conf.api.type))
			except AttributeError:
				raise ValueError('URL shortener "{}" is not supported')
			url = func(url, self.conf.api.parameters)
		return re.sub(r'^(?i)(https?|spdy)://', '', url)


	def shorten_cut(self, url, params):
		return url[:(params or 50)]

	def shorten_m29(self, url, params):
		return get_m29_url(url)


relay = Shortener
