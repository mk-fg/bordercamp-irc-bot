# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
import re

from twisted.python import log

from . import BCRelay


class RegexSub(BCRelay):

	def __init__(self, *argz, **kwz):
		super(RegexSub, self).__init__(*argz, **kwz)
		log.noise('Compiling regex: {!r}'.format(self.conf.src))
		self.regex = re.compile(self.conf.src)

	def dispatch(self, msg):
		msg_sub = self.regex.sub(self.conf.dst, msg)
		if msg == msg_sub: log.noise('RegexSub failed, msg: {!r}'.format(msg))
		return msg_sub


relay = RegexSub
