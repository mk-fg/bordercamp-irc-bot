# -*- coding: utf-8 -*-
from __future__ import print_function

class BCRelay(object):

	conf = interface = None # filled by default init

	def __init__(self, conf, interface):
		self.conf, self.interface = conf, interface

	def dispatch(self, msg):
		raise ValueError('This relay is not designed to process incoming messages')
