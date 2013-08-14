# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp import force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
import os, re, hashlib, types


class AtomOStatusLink(BCRelay):

	def __init__(self, *argz, **kwz):
		super(AtomOStatusLink, self).__init__(*argz, **kwz)

		# Pre-process warning templates
		if self.conf.warn and self.conf.warn.has_keys:
			if isinstance(self.conf.warn.has_keys, types.StringTypes):
				self.conf.warn.has_keys = [self.conf.warn.has_keys]
			warn_list = list()
			for tpl in self.conf.warn.has_keys:
				if not (tpl.startswith('{') and tpl.endswith('}')):
					tpl = '{{{}}}'.format(tpl)
				warn_list.append(tpl)
			self.conf.warn.has_keys = warn_list
			self.conf.warn.template = force_unicode(self.conf.warn.template)
		else: self.conf.warn = None

	_lookup_error = KeyError, IndexError, AttributeError

	def dispatch(self, msg):
		# Generate message id
		convo_id = 'none?'
		for link in msg.data.post.links:
			if link.rel == 'ostatus:conversation':
				convo_id = hashlib.sha1(link.href)\
					.digest().encode('base64').replace('/', '-')[:self.conf.id_length]
				break
		# Pick template
		atype, tpl = 'other', self.conf.template.other
		for atype, obj_type in [('note', r'/note$'), ('comment', r'/comment$')]:
			if not re.search(obj_type, msg.data.post['activity_object-type']): continue
			tpl = self.conf.template[atype]
			break
		# Check for RTs
		if self.conf.skip_rts:
			try: msg_base = msg.data.post.content[0].value
			except self._lookup_error: pass
			else:
				if atype == 'other' and msg_base.startswith('RT @'): return
		# Format
		res = [force_unicode(tpl).format(msg=msg, id=convo_id)]

		# Add warnings, if necessary
		if self.conf.warn:
			msg_data = msg.data._asdict()
			for tpl in self.conf.warn.has_keys:
				try: val = tpl.format(**msg_data)
				except self._lookup_error: continue
				val = dict(id=convo_id, key=tpl.strip('{}'), value=val)
				try: val = self.conf.warn.template.format(**val)
				except self._lookup_error as err:
					raise ValueError( 'Failed to format template'
						' {!r} (data: {}): {}'.format(self.conf.warn.template, val, err) )
				res.append(val)

		return res


relay = AtomOStatusLink
