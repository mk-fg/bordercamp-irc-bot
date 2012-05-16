# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from contextlib import closing
from time import time
import os, re, zmq

from twisted.python import log

from . import BCRelay


class SnortLog(BCRelay):

	def __init__(self, *argz, **kwz):
		super(SnortLog, self).__init__(*argz, **kwz)
		self.zmq_ctx = zmq.Context()
		self.zmq_optz = self.conf.traffic_dump.nflog_pipe_interface
		log.noise('Compiling regex: {!r}'.format(self.conf.sig_match))
		self.regex = re.compile(self.conf.sig_match)

	def traffic_dump(self):
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
		# Get the artifact signature id
		match = self.regex.search(msg)
		if not match:
			log.debug('Failed to match snort rule-signature in msg: {!r}'.format(msg))
			return msg
		sig = match.group('sig')

		# Check if traffic dump should be generated
		dump = False
		if sig in self.conf.traffic_dump.signatures: dump = True
		if not dump:
			for regex in self.conf.traffic_dump.match:
				if re.search(regex, msg):
					dump = True
					break
		if dump: msg = msg + '\n  dump: {}'.format(self.traffic_dump())

		return msg


relay = SnortLog
