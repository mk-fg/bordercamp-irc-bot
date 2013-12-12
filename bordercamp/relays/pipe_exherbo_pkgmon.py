# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
import os, sys, re

from twisted.internet import reactor, protocol, defer
from twisted.web.client import getPage
from twisted.python import log

from bordercamp import force_bytes
from . import BCRelay


class PkgMon(BCRelay):

	def __init__(self, *argz, **kwz):
		super(PkgMon, self).__init__(*argz, **kwz)
		log.noise('Compiling regexes: {!r}'.format(self.conf.seek))
		self.seek = map(re.compile, self.conf.seek)


	def check(self, name):
		check = self.conf.get('check_path')
		if check and check.path:
			path = check.path.format(name=name)
			log.noise('Checking package path: {}'.format(path))
			if glob(check.path.format(name=name)): return check.line
		# no other checks yet

	@defer.inlineCallbacks
	def name_from_patch_link( self, link,
			_re_path=re.compile(r'\bpackages/[\w\-]+/(?P<name>[\w\-]+)/') ):
		names = set()
		try: page = yield getPage(force_bytes(link), timeout=120)
		except Exception as err:
			log.warn('Failed to download patch: {}'.format(err))
			defer.returnValue(None)
		page = it.imap(op.methodcaller('strip'), page.splitlines())
		for line in page:
			if re.search(r'^\s*(\S+\s+\|\s+\d+\s+[\-+]*\s*$|rename |diff --git |[\-+]{3} )', line):
				line = _re_path.search(line)
				if line: names.add(line.group('name'))
		defer.returnValue(names)


	@defer.inlineCallbacks
	def dispatch(self, msg):
		for regex in self.seek:
			match = regex.search(msg)
			if not match: continue

			# Plain package name captured
			try: name = match.group('name')
			except IndexError: name = None

			# Link to a patch
			if not name:
				try: link = match.group('patch')
				except IndexError: pass
				else:
					name = yield defer.maybeDeferred(self.name_from_patch_link, link)

			if name:
				if not isinstance(name, (list, set)): name = [name]
				for name in name:
					line = self.check(name)
					if line: defer.returnValue(line.format(name=name, msg=msg))


relay = PkgMon
