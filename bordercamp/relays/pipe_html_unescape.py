# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.web.microdom import unescape
from twisted.python import log

from . import BCRelay

import itertools as it, operator as op, functools as ft


class HtmlUnescape(BCRelay):

	def dispatch(self, msg):
		return unescape(msg)


relay = HtmlUnescape
