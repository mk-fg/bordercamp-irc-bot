# -*- coding: utf-8 -*-
from __future__ import print_function

from twisted.web.client import Agent, RedirectAgent,\
	HTTPConnectionPool, HTTP11ClientProtocol, ContentDecoderAgent,\
	GzipDecoder, FileBodyProducer, ResponseDone
from twisted.web.http_headers import Headers
from twisted.web import http
from twisted.internet import defer, reactor, ssl, protocol, error, threads
from twisted.python import log

from OpenSSL import crypto

from bordercamp import force_bytes

import itertools as it, operator as op, functools as ft
import re, types, time, rfc822, io, json
import twisted, bordercamp

# Bad thing it's added there in the first place
if not hasattr(log, 'noise'): log.noise = print
if not hasattr(log, 'debug'): log.debug = print


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

@defer.inlineCallbacks
def first_result(*deferreds):
	try:
		res, idx = yield defer.DeferredList(
			deferreds, fireOnOneCallback=True, fireOnOneErrback=True )
	except defer.FirstError as err: err.subFailure.raiseException()
	defer.returnValue(res)


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

class SyncTimeout(Exception): pass
class SyncError(Exception): pass


class HTTPClient(object):

	use_cache_headers = True
	request_pool_options = dict(
		maxPersistentPerHost=10,
		cachedConnectionTimeout=600,
		retryAutomatically=True )
	ca_certs_files = b'/etc/ssl/certs/ca-certificates.crt'
	user_agent = b'bordercamp-irc-bot/{} twisted/{}'\
		.format(bordercamp.__version__, twisted.__version__)
	hide_connection_errors = False
	sync_fallback_timeout = 180 # timeout for synchronous fallback requests in a thread

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
	def sync_wrap(self, func, *argz, **kwz):
		timeout = defer.Deferred()
		reactor.callLater( self.sync_fallback_timeout,
			lambda: not timeout.called and timeout.callback(SyncTimeout) )
		def thread_wrapper():
			# Do not let exception to be raise in a thread - twisted logs these as unhandled
			try: return func(*argz, **kwz)
			except Exception as err: return SyncError(err)
		res = yield first_result(timeout, threads.deferToThread(thread_wrapper))
		if res is SyncTimeout: raise res()
		if isinstance(res, SyncError): raise res.args[0]
		defer.returnValue(res)

	@defer.inlineCallbacks
	def request(self, url, method='get', decode=None, encode=None, data=None):
		method, url = force_bytes(method).upper(), force_bytes(url)
		headers = {'User-Agent': self.user_agent}

		if method == 'GET' and self.use_cache_headers:
			# Avoid doing extra work
			cache = self.fetch_cache.get(url, dict())
			if 'cache-control' in cache and cache['cache-control'] >= time.time():
				defer.returnValue(None) # no need to re-process same thing
			if 'last-modified' in cache:
				headers['If-Modified-Since'] = rfc822date(cache['last-modified'])
			if 'etag' in cache: headers['If-None-Match'] = '"{}"'.format(cache['etag'])

		log.noise( 'HTTP request: {} {} (h: {}, enc: {}, dec: {}, data: {!r})'\
			.format(method, url[:100], headers, encode, decode, type(data)) )

		if data is not None:
			if encode is None:
				if isinstance(data, types.StringTypes): data = io.BytesIO(data)
			elif encode == 'form':
				headers.setdefault('Content-Type', 'application/x-www-form-urlencoded')
				data = io.BytesIO(urlencode(data))
			elif encode == 'json':
				headers.setdefault('Content-Type', 'application/json')
				data = io.BytesIO(json.dumps(data))
			else: raise ValueError('Unknown request encoding: {}'.format(encode))
			data = FileBodyProducer(data)
		if decode not in ['json', None]:
			raise ValueError('Unknown response decoding method: {}'.format(decode))

		requests = None # indicates fallback to requests module (for e.g. ipv6-only site)
		try:
			res = yield self.request_agent.request( method, url,
				Headers(dict((k,[v]) for k,v in (headers or dict()).viewitems())), data )
		except error.DNSLookupError:
			import requests
			try:
				res = yield self.sync_wrap(
					getattr(requests, method.lower()), url, headers=headers, data=data )
			except (requests.exceptions.RequestException, SyncTimeout) as err:
				if not self.hide_connection_errors:
					raise HTTPClientError(None, 'Lookup/connection error: {}'.format(err))
				else:
					log.debug('Lookup/connection error (supressed): {}'.format(err))
					defer.returnValue(None) # should also supress fast refetching

		code, phrase, version = (res.code, res.phrase, res.version)\
			if not requests else ( res.status_code,
				http.RESPONSES[res.status_code], ('HTTP', 1, 1) )
		log.noise( 'HTTP request done ({} {}): {} {} {}'\
			.format(method, url[:100], code, phrase, version) )
		if code in [http.NO_CONTENT, http.NOT_MODIFIED]: defer.returnValue(None)
		if code not in [http.OK, http.CREATED]: raise HTTPClientError(code, phrase)

		if not requests:
			data = defer.Deferred()
			res.deliverBody(DataReceiver(data))
			data = yield data
			headers = dict((k, v[-1]) for k,v in res.headers.getAllRawHeaders())
		else:
			try:
				data = yield self.sync_wrap(getattr, res, 'text')
				headers = yield self.sync_wrap(getattr, res, 'headers')
			except (requests.exceptions.RequestException, SyncTimeout) as err:
				raise HTTPClientError(None, 'Sync connection error: {}'.format(err))

		if method == 'GET' and self.use_cache_headers:
			cache = dict((k.lower(), v) for k,v in headers.items())
			cache = dict( (k, cache[k]) for k in
				['last-modified', 'cache-control', 'etag'] if k in cache )
			# Update headers' cache
			if 'last-modified' in cache:
				ts = rfc822.parsedate_tz(cache['last-modified'])
				cache['last-modified'] = time.mktime(ts[:9]) + (ts[9] or 0)
			if 'cache-control' in cache:
				match = re.search(r'\bmax-age=(\d+)\b', cache.pop('cache-control'))
				if match: cache['cache-control'] = time.time() + int(match.group(1))
			if cache: self.fetch_cache[url] = cache

		defer.returnValue((json.loads(data) if decode is not None else data, headers))
