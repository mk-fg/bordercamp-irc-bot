# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp.routing import RelayedEvent
from bordercamp import force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
from collections import defaultdict
import os, re, time, types


class AuditLog(BCRelay):

	_re_base = re.compile(
		ur'\bnode=(?P<node>\S+)\s+type=(?P<type>\S+)'
		ur'\s+msg=audit\((?P<ev_id>[\d.:]+)\):\s*(?P<msg>.*)$' )

	_lookup_error = KeyError, IndexError, AttributeError

	def _ev_cache_gc(self):
		if ord(os.urandom(1)) < 10: # 4% chance
			ts_min = time.time() - self._ev_cache_timeout
			for k, ev in self._ev_cache.items():
				ts_ev = ev.get('ts')
				if ts_ev is not None and ts_ev < ts_min:
					ev = self._ev_cache.pop(k)
					(log.warn if self.conf.processing.warn else log.noise)\
						('Unprocessed audit event in cache: {!r}'.format(ev))

	def __init__(self, *argz, **kwz):
		super(AuditLog, self).__init__(*argz, **kwz)
		self._ev_cache = dict()
		self._ev_cache_timeout = self.conf.processing.timeout
		for v in self.conf.events.viewvalues():
			if not v.ev_keys: v.ev_keys = list()
			elif isinstance(v.ev_keys, types.StringTypes): v.ev_keys = [v.ev_keys]

	_no_fallback = object()
	def get_msg_val(self, msg, k, val=ur'(?P<val>\d+)', fallback=_no_fallback):
		match = re.search(ur'\b{}=({})(\s+|$)'.format(re.escape(k), val), msg)
		if not match:
			if fallback is self._no_fallback: raise KeyError(msg, k)
			else: return fallback
		return match.group('val')

	def dispatch(self, msg):
		if not msg.strip(): return

		## Event lines are cached until EOE msg is encountered
		match = self._re_base.search(msg)
		if not match:
			log.warn('Failed to match audit event spec: {!r}'.format(msg))
			return

		node, ev_id, ev_type, msg = (match.group(k) for k in ['node', 'ev_id', 'type', 'msg'])
		ev_key = node, ev_id

		if ev_key not in self._ev_cache:
			self._ev_cache[ev_key] = defaultdict(list)
			self._ev_cache[ev_key].update(ts=time.time(), node=node, ev_id=ev_id)
			self._ev_cache_gc()
		ev = self._ev_cache[ev_key]

		if ev_type != 'EOE': # cache event data
			ev[ev_type].append(msg)
			return
		del self._ev_cache[ev_key]

		## Get "key" value for event, if present
		ev_key = None
		try: syscall, = ev['SYSCALL'] # currently handled events always have it
		except ValueError: pass
		else:
			try: ev_key = self.get_msg_val(syscall, 'key', ur'"(?P<val>[^"]+)"')
			except KeyError as err:
				log.noise('Failed to get ev_key from syscall: {}'.format(err))
		if not ev_key:
			log.noise('Unhandled event: {!r}'.format(ev))
			return

		## Processing

		if ev_key in self.conf.events.watches.ev_keys:
			# Extract all necessary attributes
			ev_vals = dict(node=ev['node'], ev_id=ev['ev_id'], key=ev_key)
			for k in it.imap(''.join, it.product(['', 'e', 's', 'fs'], ['uid', 'gid'])):
				ev_vals[k] = self.get_msg_val(syscall, k)
			for k in 'comm', 'exe':
				ev_vals[k] = self.get_msg_val(syscall, k, ur'"(?P<val>[^"]+)"')
			ev_vals['tty'] = self.get_msg_val(syscall, 'tty', '(?P<val>\S+)')
			paths = ev_vals['paths'] = list()
			for msg in ev['PATH']:
				path = self.get_msg_val(msg, 'name', ur'(?P<val>"[^"]+"|\(null\)|[0-9A-F]+)')
				paths.append(dict( path=path,
					inode=self.get_msg_val(msg, 'inode', fallback='nil'),
					dev=self.get_msg_val(msg, 'dev', '(?P<val>[a-f\d]{2}:[a-f\d]{2})', fallback='nil') ))

			# Formatting
			err, tpl = None, force_unicode(self.conf.events.watches.template_path)
			ev_vals['paths'] = list()
			for val in paths:
				try: ev_vals['paths'].append(tpl.format(**val))
				except self._lookup_error as err: break
			if not err:
				ev_vals['paths'] = ', '.join(ev_vals['paths'])
				tpl, val = force_unicode(self.conf.events.watches.template), ev_vals
				try: event = tpl.format(**val)
				except self._lookup_error as err: pass
				event = RelayedEvent(event)
				event.data = ev_vals
				return event
			raise ValueError( 'Failed to format template {!r} (data: {}): {}'.format(tpl, val, err))


relay = AuditLog
