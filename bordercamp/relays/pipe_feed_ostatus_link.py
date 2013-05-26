# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp import force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
import os, re, hashlib


class AtomOStatusLink(BCRelay):

	def __init__(self, *argz, **kwz):
		super(AtomOStatusLink, self).__init__(*argz, **kwz)

	def dispatch(self, msg):
		convo_id = 'none?'
		for link in msg.data.post.links:
			if link.rel == 'ostatus:conversation':
				convo_id = hashlib.sha1(link.href)\
					.digest().encode('base64').replace('/', '-')[:self.conf.id_length]
				break
		tpl = self.conf.template.other
		for k, obj_type in [('note', r'/note$'), ('comment', r'/comment$')]:
			if not re.search(obj_type, msg.data.post['activity_object-type']): continue
			tpl = self.conf.template[k]
			break
		return force_unicode(tpl).format(msg=msg, id=convo_id)


relay = AtomOStatusLink
