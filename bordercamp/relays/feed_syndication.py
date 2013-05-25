# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.internet import defer, reactor
from twisted.python import log

import feedparser

from bordercamp.routing import RelayedEvent
from bordercamp.http import HTTPClient
from bordercamp import force_bytes
from . import BCRelay

import itertools as it, operator as op, functools as ft
from collections import namedtuple
import types, random, hashlib, sqlite3


class PostHashDB(object):

	db = db_init = None

	def __init__(self, db_path):
		self.db = sqlite3.connect(db_path)
		self.db.text_factory = bytes
		self.db.executescript( 'CREATE TABLE IF NOT EXISTS processed'
			' (hash BLOB PRIMARY KEY ON CONFLICT REPLACE NOT NULL);' )

	def __del__(self):
		if self.db:
			self.db.close()
			self.db = None

	def __contains__(self, k):
		with self.db:
			cur = self.db.execute('SELECT 1 FROM processed WHERE hash = ? LIMIT 1', (k,))
			try: return bool(cur.fetchone())
			finally: cur.close()

	def add(self, k):
		if k in self: return
		with self.db: self.db.execute('INSERT INTO processed (hash) VALUES (?)', (k,)).close()


class FeedEntryInfo(namedtuple('FeedEntryInfo', 'feed post conf')):
	__slots__ = ()

	def get_by_path(self, spec):
		if isinstance(spec, types.StringTypes): spec = [spec]
		spec = list(reversed(list(spec)))
		while spec:
			k = spec.pop()
			if not k: return '' # empty fallback
			try:
				val = op.attrgetter(k)(self)
				if not val: raise AttributeError(k)
			except AttributeError:
				if not spec: raise
			else: return val
		if not spec: raise ValueError('Invalid attr-spec: {!r}'.format(spec))


class FeedSyndication(BCRelay):

	feeds = None

	def __init__(self, *argz, **kwz):
		super(FeedSyndication, self).__init__(*argz, **kwz)

		self.client = HTTPClient(
			use_cache_headers=self.conf.use_cache_headers,
			request_pool_options=self.conf.request_pool_options,
			ca_certs_files=self.conf.ca_certs_files, user_agent=self.conf.user_agent )

		self.feeds = dict()
		base = self.conf.feeds.pop('_default')
		for url, opts in self.conf.feeds.viewitems():
			opts.rebase(base)
			opts.template = opts.template.decode('utf-8')
			self.feeds[url] = opts
			self.schedule_fetch(url, startup=True)

		self.filter_db = set() if not self.conf.deduplication_cache\
			else PostHashDB(self.conf.deduplication_cache)

	def schedule_fetch(self, url, startup=False):
		interval = self.feeds[url].interval
		interval = (interval.jitter * interval.base * random.random())\
			if startup and interval.fetch_on_startup\
			else (interval.base + ( interval.jitter * interval.base
				* random.random() * random.choice([-1, 1]) ))
		log.noise('Scheduling fetch for feed (url: {}) in {}s'.format(url, interval))
		reactor.callLater(interval, self.fetch_feed, url)

	def dispatch_filter(self, post_hash):
		assert isinstance(post_hash, bytes)
		if post_hash in self.filter_db: return False
		self.filter_db.add(post_hash)
		return True

	@defer.inlineCallbacks
	def fetch_feed(self, url):
		data = yield self.client.fetch(url)
		if data is None: defer.returnValue(None) # cache hit or not modified
		feed, headers = data

		parser = feedparser.parse(feed, response_headers=headers)
		for post in reversed(parser.entries):
			post_obj = FeedEntryInfo(parser.feed, post, self.conf)

			post_hash = hashlib.sha256('\0'.join(
				force_bytes(post_obj.get_by_path(attr))
				for attr in self.feeds[url].deduplication )).digest()
			if not self.dispatch_filter(post_hash): continue

			event = RelayedEvent(self.feeds[url].template.format(**post_obj._asdict()))
			event.data = post_obj # for any further tricky filtering
			reactor.callLater(0, self.interface.dispatch, event, source=self)

		self.schedule_fetch(url) # next one


relay = FeedSyndication
