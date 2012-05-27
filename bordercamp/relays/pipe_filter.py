# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from collections import OrderedDict, deque, defaultdict
from time import time
import re

from twisted.python import log

from . import BCRelay


class FilterPipe(BCRelay):

	def __init__(self, *argz, **kwz):
		super(FilterPipe, self).__init__(*argz, **kwz)
		self.rules = OrderedDict()
		for name,rule in self.conf.rules.viewitems():
			log.noise('Compiling filter (name: {}): {!r}'.format(name, rule.regex))
			try: action, optz = rule.action.split('-', 1)
			except ValueError: action, optz = rule.action, list()
			else:
				if action == 'limit': optz = map(int, optz.split('/'))
				else: optz = [optz]
			self.rules[name] = re.compile(rule.regex), action, optz
		self.rule_hits, self.rule_notes, self.rule_drops = dict(), set(), defaultdict(int)

	def dispatch(self, msg):
		for name, (pat, action, optz) in self.rules.viewitems():
			if not pat.search(msg): continue

			if action == 'limit':
				if name not in self.rule_hits: self.rule_hits[name] = deque()
				win, ts, (c, t) = self.rule_hits[name], time(), optz
				ts_thresh = ts - t
				win.append(ts)
				while win[0] < ts_thresh: win.popleft()
				rate = len(win)
				if rate > c:
					log.noise(( 'Rule ({}) triggering rate'
						' above threshold ({}/{}): {}' ).format(name, c, t, rate))
					self.rule_drops[name] += 1
					if name not in self.rule_notes:
						self.rule_notes.add(name)
						return ( '  ...limiting messages matching'
								' filter-rule {} ({}/{}, dropped (for uptime): {})' )\
							.format(name, c, t, self.rule_drops[name])
					else: return
				self.rule_notes.discard(name)
				return msg

			elif action == 'allow': return msg
			elif action == 'drop': return

		if self.conf.policy == 'allow': return msg


relay = FilterPipe
