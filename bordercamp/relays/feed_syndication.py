# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.web.client import Agent, RedirectAgent,\
	HTTPConnectionPool, HTTP11ClientProtocol, ContentDecoderAgent,\
	GzipDecoder, FileBodyProducer, ResponseDone
from twisted.web.http_headers import Headers
from twisted.web import http
from twisted.internet import defer, reactor, ssl, task, protocol
from twisted.python import log

from OpenSSL import crypto
import feedparser
from lya import AttrDict

from bordercamp.routing import RelayedEvent
from bordercamp import force_bytes
from . import BCRelay

import itertools as it, operator as op, functools as ft
from collections import namedtuple
import re, types, time, logging, rfc822, random, hashlib, sqlite3
import twisted, bordercamp



# Based on twisted.mail.smtp.rfc822date, always localtime
def rfc822date(ts=None):
	timeinfo = time.localtime(ts)
	tz = -(time.altzone if timeinfo[8] else time.timezone)
	tzhr, tzmin = divmod(abs(tz), 3600)
	if tz: tzhr *= int(abs(tz)//tz)
	tzmin, tzsec = divmod(tzmin, 60)
	return '%s, %02d %s %04d %02d:%02d:%02d %+03d%02d' % (
		['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'][timeinfo[6]],
		timeinfo[2],
		[ 'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
			 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec' ][timeinfo[1] - 1],
		timeinfo[0], timeinfo[3], timeinfo[4], timeinfo[5],
		tzhr, tzmin )


class DataReceiver(protocol.Protocol):

	def __init__(self, done):
		self.done, self.data = done, list()

	def dataReceived(self, chunk):
		self.data.append(chunk)

	def connectionLost(self, reason):
		self.done.callback(b''.join(self.data)\
			if isinstance(reason.value, ResponseDone) else reason)


class TLSContextFactory(ssl.CertificateOptions):

	isClient = 1

	def __init__(self, ca_certs_files):
		ca_certs = dict()

		for ca_certs_file in ( [ca_certs_files]
				if isinstance(ca_certs_files, types.StringTypes) else ca_certs_files ):
			with open(ca_certs_file) as ca_certs_file:
				ca_certs_file = ca_certs_file.read()
			for cert in re.findall( r'(-----BEGIN CERTIFICATE-----'
					r'.*?-----END CERTIFICATE-----)', ca_certs_file, re.DOTALL ):
				cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
				ca_certs[cert.digest('sha1')] = cert

		super(TLSContextFactory, self).__init__(verify=True, caCerts=ca_certs.values())

	def getContext(self, hostname, port):
		return super(TLSContextFactory, self).getContext()


class QuietHTTP11ClientFactory(protocol.Factory):
	noisy = False
	def __init__(self, quiescentCallback):
		self._quiescentCallback = quiescentCallback
	def buildProtocol(self, addr):
		return HTTP11ClientProtocol(self._quiescentCallback)


class QuietHTTPConnectionPool(HTTPConnectionPool):
	_factory = QuietHTTP11ClientFactory


class HTTPClientError(Exception):
	def __init__(self, code, msg):
		super(HTTPClientError, self).__init__(code, msg)
		self.code = code


class HTTPClient(object):

	use_cache_headers = True
	request_pool_options = dict(
		maxPersistentPerHost=10,
		cachedConnectionTimeout=600,
		retryAutomatically=True )
	ca_certs_files = b'/etc/ssl/certs/ca-certificates.crt'
	user_agent = b'bordercamp-irc-bot/{} twisted/{}'\
		.format(bordercamp.__version__, twisted.__version__)

	def __init__(self, **kwz):
		for k, v in kwz.viewitems():
			getattr(self, k) # to somewhat protect against typos
			if v is not None: setattr(self, k, v)

		pool = QuietHTTPConnectionPool(reactor, persistent=True)
		for k, v in self.request_pool_options.viewitems():
			getattr(pool, k) # to somewhat protect against typos
			setattr(pool, k, v)
		self.request_agent = ContentDecoderAgent(RedirectAgent(Agent(
			reactor, TLSContextFactory(self.ca_certs_files), pool=pool )), [('gzip', GzipDecoder)])

		self.fetch_cache = dict() # {url: {header_name: processed_value, ...}, ...}

	@defer.inlineCallbacks
	def fetch(self, url):
		if isinstance(url, unicode): url = url.encode('utf-8')
		headers = {'User-Agent': self.user_agent}

		if self.use_cache_headers:
			# Avoid doing extra work
			cache = self.fetch_cache.get(url, dict())
			if 'cache-control' in cache and cache['cache-control'] >= time.time():
				defer.returnValue(None) # no need to re-process same thing
			if 'last-modified' in cache:
				headers['If-Modified-Since'] = rfc822date(cache['last-modified'])
			if 'etag' in cache: headers['If-None-Match'] = '"{}"'.format(cache['etag'])

		log.noise('HTTP request: GET {} (h: {})'.format(url[:100], headers))

		res = yield self.request_agent.request( 'GET', url,
			Headers(dict((k,[v]) for k,v in (headers or dict()).viewitems())) )
		code = res.code
		log.noise( 'HTTP request done (GET {}): {} {} {}'\
			.format(url[:100], code, res.phrase, res.version) )
		if code in [http.NO_CONTENT, http.NOT_MODIFIED]: defer.returnValue(None)
		if code not in [http.OK, http.CREATED]: raise HTTPClientError(code, res.phrase)

		data = defer.Deferred()
		res.deliverBody(DataReceiver(data))

		if self.use_cache_headers:
			# Update headers' cache
			cache = dict( (k.lower(), res.headers.getRawHeaders(k)[-1])
				for k in ['Last-Modified', 'Cache-Control', 'ETag'] if res.headers.hasHeader(k) )
			if 'last-modified' in cache:
				ts = rfc822.parsedate_tz(cache['last-modified'])
				cache['last-modified'] = time.mktime(ts[:9]) + (ts[9] or 0)
			if 'cache-control' in cache:
				match = re.search(r'\bmax-age=(\d+)\b', cache.pop('cache-control'))
				if match: cache['cache-control'] = time.time() + int(match.group(1))
			if cache: self.fetch_cache[url] = cache

		defer.returnValue(( (yield data),
			dict((k, v[-1]) for k,v in res.headers.getAllRawHeaders()) ))



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
