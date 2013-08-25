# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp.routing import RelayedEvent
from bordercamp import force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
from collections import defaultdict
import os, re, time


class AuditLog(BCRelay):

	_re_base = re.compile(
		ur'\bnode=(?P<node>\S+)\s+type=(?P<type>[A-Z]+)'
		ur'\s+msg=audit\((?P<ev_id>[\d.:]+)\):\s*(?P<msg>.*)$' )

	_lookup_error = KeyError, IndexError, AttributeError

	_ev_cache = None
	_ev_cache_timeout = 3600
	def _ev_cache_gc(self):
		if ord(os.urandom(1)) < 10: # 4% chance
			ts_min = time.time() - self._ev_cache_timeout
			for k, ev in self._ev_cache.items():
				ts_ev = ev.get('ts')
				if ts_ev is not None and ts_ev < ts_min:
					ev = self._ev_cache.pop(k)
					log.warn('Unprocessed audit event in cache: {!r}'.format(ev))

	def __init__(self, *argz, **kwz):
		super(AuditLog, self).__init__(*argz, **kwz)
		self._ev_cache = dict()

	def get_msg_val(self, msg, k, val=ur'(?P<val>\d+)'):
		match = re.search(ur'\b{}=({})(\s+|$)'.format(re.escape(k), val), msg)
		if not match: raise KeyError(msg, k)
		return match.group('val')

	def dispatch(self, msg):
		if not msg.strip(): return

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

		if self.conf.events.watches.enabled:
			# Extract all necessary attributes
			ev_vals = dict(node=ev['node'], ev_id=ev['ev_id'])
			try: syscall, = ev['SYSCALL']
			except ValueError:
				raise ValueError('Failed to dissect watch-event: {!r}'.format(ev))
			for k in it.imap(''.join, it.product(['', 'e', 's', 'fs'], ['uid', 'gid'])):
				ev_vals[k] = self.get_msg_val(syscall, k)
			for k in 'key', 'comm', 'exe':
				ev_vals[k] = self.get_msg_val(syscall, k, ur'"(?P<val>[^"]+)"')
			ev_vals['tty'] = self.get_msg_val(syscall, 'tty', '(?P<val>\S+)')
			paths = ev_vals['paths'] = list()
			for msg in ev['PATH']:
				path = self.get_msg_val(msg, 'name', ur'(?P<val>"[^"]+"|\(null\))')
				paths.append(dict( path=path,
					inode=self.get_msg_val(msg, 'inode'),
					dev=self.get_msg_val(msg, 'dev', '(?P<val>[a-f\d]{2}:[a-f\d]{2})') ))

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
