# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
import os, re, zmq

from twisted.python import log

from . import BCRelay


class NFLogDump(BCRelay):

	def __init__(self, *argz, **kwz):
		super(NFLogDump, self).__init__(*argz, **kwz)
		self.zmq_ctx = zmq.Context()
		self.zmq_optz = self.conf.traffic_dump.nflog_pipe_interface
		log.noise('Compiling regexes: {!r}'.format(self.conf.patterns))
		self.patterns = dict((pat, re.compile(pat)) for pat in self.conf.patterns)
		self.last_dump = 0

	def traffic_dump(self, ts=None):
		ts = ts or time()
		with closing(self.zmq_ctx.socket(zmq.REQ)) as sock:
			for k in zmq.RCVTIMEO, zmq.SNDTIMEO:
				sock.setsockopt(k, int(self.zmq_optz.timeout * 1e3))
			log.debug('Sending traffic-dump request')
			sock.connect(self.zmq_optz.socket)
			sock.send('q')
			dump_name = self.conf.traffic_dump.path.format(ts=int(time()))
			with open(dump_name, 'wb') as dst:
				dst.write(sock.recv())
				while sock.getsockopt(zmq.RCVMORE): dst.write(sock.recv())
		return os.path.basename(dump_name)

	def dispatch(self, msg):
		for pat,pat_re in self.patterns.viewitems():
			if pat_re.search(msg):
				log.debug('Matched nflog-dump pattern: {}'.format(pat))
				break
		else: return

		if self.conf.traffic_dump.min_interval\
				and self.last_dump > time() - self.conf.traffic_dump.min_interval:
			log.debug( 'Ignoring nflog-dump'
				' pattern match ({}) due to rate-limiting'.format(pat) )
			return
		self.last_dump = time()

		msg = 'Matched nflog-dump pattern: {}'.format(pat)
		try: dump = self.traffic_dump(ts=self.last_dump)
		except Exception as err:
			msg += '\n  dump failed: {}'.format(err)
		else: msg += '\n  dump: {}'.format(dump)

		return msg


relay = NFLogDump
