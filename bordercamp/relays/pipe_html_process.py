# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.python import log

from bordercamp.routing import RelayedEvent
from bordercamp import force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
import re


class HtmlProcess(BCRelay):

	def lxml_soup(self, string):
		'Safe processing of any tag soup (which is a norm on the internets).'
		from lxml.html import fromstring as lxml_fromstring
		from lxml.etree import (
			XMLSyntaxError as lxml_SyntaxError,
			ParserError as lxml_ParserError )
		try: doc = lxml_fromstring(force_unicode(string))
		except (lxml_SyntaxError, lxml_ParserError): # last resort for "tag soup"
			from lxml.html.soupparser import fromstring as soup
			doc = soup(force_unicode(string))
		return doc

	def dispatch(self, msg):
		msg_etree = self.lxml_soup(msg)
		if self.conf.process_links:
			for tag in msg_etree.iter(tag='a'):
				if tag.text and not re.search(ur'https?://', tag.text):
					tag.text = u'{} <{}>'.format(tag.text, tag.attrib['href'])
				tag.drop_tag()
		msg_new = msg_etree.text_content()
		if isinstance(msg, RelayedEvent) and hasattr(msg, 'data'):
			msg_new = RelayedEvent(msg_new)
			msg_new.data = msg.data
		return msg_new


relay = HtmlProcess
