# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp import force_bytes, force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
import os, re, anydbm


class SnortRefs(BCRelay):

	def __init__(self, *argz, **kwz):
		super(SnortRefs, self).__init__(*argz, **kwz)
		log.noise('Compiling regex: {!r}'.format(self.conf.sig_match))
		self.regex = re.compile(self.conf.sig_match)
		self.gid_ignore = set(it.imap(str, ( [self.conf.gid_ignore]
				if isinstance(self.conf.gid_ignore, (int, str)) else self.conf.gid_ignore )))\
			if self.conf.gid_ignore else set()
		self.sid_db_ts = 0


	def update_sid_db( self,
			_ref_line=re.compile( r'^\s*config\s+reference:'
				r'\s+(?P<ref_type>\w+)\s+(?P<ref_url>\S+)\s*$' ) ):
		log.debug('Updating sid-msg.map hash: {}'.format(self.conf.paths.sid_db))

		# Process ref types config (ref_type:url mapping)
		ref_map = dict()
		if self.conf.paths.refs:
			with open(self.conf.paths.refs) as src:
				for line in src:
					match = _ref_line.search(line)
					if not match: continue
					ref_map[match.group('ref_type').lower()] = match.group('ref_url')

		# (Re)build sid:urls db
		try: os.unlink(self.conf.paths.sid_db)
		except OSError: pass
		with open(self.conf.paths.sid_src) as src,\
				closing(anydbm.open(self.conf.paths.sid_db, 'c')) as dst:
			for line in src:
				line = line.strip()
				if not line or line[0] == '#': continue
				try:
					sid, msg, refs = op.itemgetter(0, 1, slice(2, None))\
						(map(op.methodcaller('strip'), line.split(' || ')))
				except IndexError:
					log.warn('Unrecognized sid-msg.map line format, ignoring: {!r}'.format(line))
				if not sid.isdigit():
					log.warn('Detected non-numeric sid: {!r} (line: {!r})'.format(sid, line))
				ref_urls = list()
				for ref in refs:
					if ref_map:
						try:
							ref_type, ref = it.imap(op.methodcaller('strip'), ref.split(',', 1))
							ref = ''.join([ref_map[ref_type.lower()], ref])
						except ValueError:
							log.warn('Unrecognized ref format, ignoring: {!r} (line: {!r})'.format(ref, line))
							continue
						except KeyError:
							log.warn( 'Unrecognized ref type:'
								' {!r} (ref: {!r}, line: {!r})'.format(ref_type, ref, line) )
							ref = ','.join([ref_type, ref])
					ref_urls.append(ref)
				if ref_urls:
					dst[sid] = ' '.join(sorted(set(dst.get(sid, '').split()).union(ref_urls)))


	def dispatch(self, msg):
		match = self.regex.search(msg)
		if not match:
			log.debug('Failed to match snort rule-sid in msg: {!r}'.format(msg))
			return msg
		sid = match.group('sid')

		if self.gid_ignore:
			try: gid = match.group('gid')
			except IndexError: pass
			else:
				if gid in self.gid_ignore: return msg

		ts = time()
		if self.sid_db_ts < ts - self.conf.sid_db_mtime_check_interval:
			if not os.path.exists(self.conf.paths.sid_db)\
					or max(0, *( os.stat(p).st_mtime
						for p in [self.conf.paths.sid_src, self.conf.paths.refs]
						if os.path.exists(p) )) > os.stat(self.conf.paths.sid_db).st_mtime:
				self.update_sid_db()
			self.sid_db = anydbm.open(self.conf.paths.sid_db)

		try: ref = force_unicode(self.sid_db[force_bytes(sid)])
		except KeyError:
			log.info('Failed to find refs for sid: {!r} (msg: {!r})'.format(sid, msg))
		else: msg += u'\n  refs: {}'.format(ref)
		return msg


relay = SnortRefs
