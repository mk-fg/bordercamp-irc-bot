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
		for name, rule in self.conf.rules.viewitems():
			if 'regex' in rule:
				log.noise('Compiling filter (name: {}): {!r}'.format(name, rule.regex))
				check = re.compile(rule.regex)
			else: check = None # boolean rule

			try: action, optz = rule.action.split('-', 1)
			except ValueError: action, optz = rule.action, list()
			else:
				if action == 'limit': optz = map(int, optz.split('/'))
				else: optz = [optz]

			self.rules[name] = check, action, optz, rule.get('match')
		self.rule_hits, self.rule_notes, self.rule_drops = dict(), set(), defaultdict(int)

	def dispatch(self, msg):
		for name, (check, action, optz, attr) in self.rules.viewitems():
			try: msg_match = msg if not attr else (op.attrgetter(attr)(msg) or '')
			except AttributeError: msg_match = ''

			if not ( check.search(msg_match)
					if check is not None else bool(msg_match) ):
				if 'nomatch' in optz:
					if action == 'allow': return msg
					elif action == 'drop': return
				continue

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

			elif 'nomatch' not in optz:
				if action == 'allow': return msg
				elif action == 'drop': return

		if self.conf.policy == 'allow': return msg


relay = FilterPipe
