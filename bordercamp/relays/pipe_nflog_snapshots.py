# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
import os, re

from twisted.python import log

from . import BCRelay


class NFLogDump(BCRelay):

	def __init__(self, *argz, **kwz):
		super(NFLogDump, self).__init__(*argz, **kwz)
		import zmq
		self.zmq = zmq
		self.zmq_ctx = self.zmq.Context()
		self.zmq_optz = self.conf.traffic_dump.nflog_pipe_interface
		log.noise('Compiling regexes: {!r}'.format(self.conf.patterns))
		self.patterns = dict((pat, re.compile(pat)) for pat in self.conf.patterns)
		self.last_dump = 0

	def traffic_dump(self, ts=None):
		ts = ts or time()
		with closing(self.zmq_ctx.socket(self.zmq.REQ)) as sock:
			for k in self.zmq.RCVTIMEO, self.zmq.SNDTIMEO:
				sock.setsockopt(k, int(self.zmq_optz.timeout * 1e3))
			log.debug('Sending traffic-dump request')
			sock.connect(self.zmq_optz.socket)
			sock.send('q')
			dump_name = self.conf.traffic_dump.path.format(ts=int(time()))
			with open(dump_name, 'wb') as dst:
				dst.write(sock.recv())
				while sock.getsockopt(self.zmq.RCVMORE): dst.write(sock.recv())
		return os.path.basename(dump_name)

	def dispatch(self, msg):
		for pat,pat_re in self.patterns.viewitems():
			if pat_re.search(msg):
				log.debug('Matched nflog-dump pattern: {}'.format(pat))
				break
		else: return

		ts = time()
		if self.conf.traffic_dump.min_interval\
				and self.last_dump > ts - self.conf.traffic_dump.min_interval:
			log.debug( 'Ignoring nflog-dump pattern match'
					' ({}) due to rate-limiting (elapsed: {:.1f}, min: {})'\
				.format(pat, ts-self.last_dump, self.conf.traffic_dump.min_interval) )
			return
		self.last_dump = ts

		msg = 'Matched nflog-dump pattern: {}'.format(pat)
		try: dump = self.traffic_dump(ts=ts)
		except Exception as err:
			msg += '\n  dump failed: {}'.format(err)
		else: msg += '\n  dump: {}'.format(dump)

		return msg


relay = NFLogDump
