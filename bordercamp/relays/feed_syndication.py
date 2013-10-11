# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.internet import defer, reactor
from twisted.web.microdom import unescape
from twisted.python import log

from bordercamp.routing import RelayedEvent
from bordercamp.http import HTTPClient, HTTPClientError
from bordercamp import force_bytes, force_unicode
from . import BCRelay

import itertools as it, operator as op, functools as ft
from collections import namedtuple
from time import time
import types, random, hashlib, json, sqlite3


class PostHashDB(object):

	db = db_init = None

	def __init__(self, db_path=':memory:', cleanup_opts=None):
		self.db = sqlite3.connect(db_path)
		self.db.text_factory = bytes
		self.db.executescript(
			'CREATE TABLE IF NOT EXISTS processed_v2'
				' (feed blob not null, hash blob not null primary'
					" key on conflict replace, ts timestamp default (strftime('%s', 'now')));"
			' CREATE INDEX IF NOT EXISTS processed_v2_ts ON processed_v2 (ts);'
			' DROP TABLE IF EXISTS processed;' )
		self.cleanup_opts = cleanup_opts

	def __del__(self):
		if self.db:
			self.db.close()
			self.db = None

	def hash(self, val):
		if not isinstance(val, types.StringTypes): val = '\0'.join(val)
		val = force_bytes(val)
		return hashlib.sha256(val).digest()

	def cleanup(self, link):
		if not self.cleanup_opts\
			or random.random() > self.cleanup_opts.cleanup_chance: return
		ts_max = self.cleanup_opts.timeout_days * 24 * 3600 - time()
		cur = link.execute( 'SELECT hash FROM processed_v2'
			' ORDER BY ts DESC LIMIT ?', (self.cleanup_opts.per_feed_min,) )
		hashes = map(op.itemgetter(0), cur.fetchall())
		cur.close()
		link.execute( ( 'DELETE FROM processed_v2'
				' WHERE ts < ? AND hash NOT IN ({})' )\
			.format(', '.join(['?']*len(hashes))), tuple([ts_max] + hashes) ).close()

	def _check(self, fk=None):
		with self.db as link:
			cur = link.execute( 'SELECT 1 FROM'
				' processed_v2 WHERE hash = ? LIMIT 1', (fk,) )
			try: return bool(cur.fetchone())
			finally: cur.close()

	def check(self, feed, k):
		return self._check(self.hash(feed) + self.hash(k))

	def add(self, feed, k):
		feed_hash, k_hash = self.hash(feed), self.hash(k)
		if self._check(feed_hash + k_hash): return False
		with self.db as link:
			link.execute( 'INSERT INTO processed_v2 (feed, hash)'
				' VALUES (?, ?)', (feed_hash, feed_hash + k_hash) ).close()
			self.cleanup(link)
		return True


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
			except (AttributeError, KeyError):
				if not spec:
					raise KeyError( 'Failed to get critical'
						' attribute {!r}, data: {!r}'.format(spec, self) )
			else: return val
		if not spec: raise ValueError('Invalid attr-spec: {!r}'.format(spec))


class FeedSyndication(BCRelay):

	feeds = None

	def __init__(self, *argz, **kwz):
		super(FeedSyndication, self).__init__(*argz, **kwz)

		self.client = HTTPClient(
			use_cache_headers=self.conf.use_cache_headers,
			request_pool_options=self.conf.request_pool_options,
			ca_certs_files=self.conf.ca_certs_files,
			user_agent=self.conf.user_agent,
			hide_connection_errors=self.conf.hide_connection_errors )

		self.feeds = dict()
		base = self.conf.feeds.pop('_default')
		for url, opts in self.conf.feeds.viewitems():
			opts.rebase(base)
			if isinstance(opts.template, types.StringTypes):
				opts.template = [opts.template]
			opts.template = map(force_unicode, opts.template)
			assert opts.type in ['feed', 'reddit-json'],\
				'Feed type must be either "feed" or "reddit-json", not {!r}'.format(self.feeds[url].type)
			self.feeds[url] = opts
			self.schedule_fetch(url, fast=opts.interval.fetch_on_startup)

		self.filter_db = PostHashDB(
			self.conf.deduplication_cache.path,
			self.conf.deduplication_cache.keep )

	def schedule_fetch(self, url, fast=False):
		interval = self.feeds[url].interval
		jitter = interval.jitter * interval.base * random.random()
		interval = jitter if fast else (interval.base + (jitter * random.choice([-1, 1])))
		log.noise('Scheduling fetch for feed (url: {}) in {}s'.format(url, interval))
		reactor.callLater(interval, self.fetch_feed, url)

	@defer.inlineCallbacks
	def fetch_feed(self, url):
		feed_type = self.feeds[url].type

		err = None
		try: data = yield self.client.request(url)
		except HTTPClientError as err:
			log.warn('Failed to fetch feed ({}): {}'.format(url, err))
			data = None
		finally: self.schedule_fetch(url, fast=bool(err)) # do faster re-fetch on errors

		if data is None: defer.returnValue(None) # cache hit, not modified, error
		data, headers = data

		if feed_type == 'feed':
			import feedparser
			parser = feedparser.parse(data, response_headers=headers)
			feed, posts = parser.feed, parser.entries
		elif feed_type == 'reddit-json':
			from lya import AttrDict # mandatory dep anyway
			data = json.loads(data)['data']
			posts = list(AttrDict(post['data']) for post in data.pop('children'))
			feed = AttrDict(data)
		else:
			raise ValueError('Unrecognized feed type: {!r}'.format(self.feeds[url].type))

		count = 0
		for post in reversed(posts):
			if feed_type == 'reddit-json':
				# Some reddit-api-specific encoding hacks
				try: title = unescape(post['title'])
				except KeyError: pass
				else: post.title = title

			post_obj = FeedEntryInfo(feed, post, self.conf)

			post_id = list(
				force_bytes(post_obj.get_by_path(attr))
				for attr in self.feeds[url].deduplication )
			if not self.filter_db.add(url, post_id): continue

			first_err = None
			for template in self.feeds[url].template:
				try: event = template.format(**post_obj._asdict())
				except (KeyError, IndexError, AttributeError) as err:
					if not first_err:
						first_err = ValueError(
							'Failed to format template {!r} (data: {}): {}'\
							.format(template, post_obj, err) )
					continue
				event = RelayedEvent(event)
				event.data = post_obj # for any further tricky filtering
				reactor.callLater(0, self.interface.dispatch, event, source=self)
				break
			else: raise first_err # all templates failed

			count += 1
			if self.feeds[url].process_max and count >= self.feeds[url].process_max: break


relay = FeedSyndication
