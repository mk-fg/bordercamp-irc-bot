# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
from fnmatch import fnmatch
from hashlib import sha1
import os, sys, re, pickle

from xattr import xattr

from twisted.python.filepath import FilePath
from twisted.internet import inotify, reactor, defer
from twisted.python import log

from . import BCRelay



class ReliableInotify(inotify.INotify):

	def __init__( self, paths_watch, callback, errback,
			mask=inotify.IN_CREATE | inotify.IN_MODIFY ):
		inotify.INotify.__init__(self)

		# Might as well start it here
		self.startReading()
		self.errback = errback
		for path in paths_watch:
			log.debug('Adding watcher for path: {}'.format(path))
			self.watch(path, mask=mask, callbacks=[callback])

	def connectionLost(self, reason):
		log.warn( 'Detected inotify'
			' connectionLost event, reason: {}'.format(reason) )
		self.errback(reason)



class Logtail(BCRelay):


	def __init__(self, *argz, **kwz):
		super(Logtail, self).__init__(*argz, **kwz)

		paths_watch = self.paths_watch = dict()
		self.paths_pos, self.paths_buff = dict(), dict()

		masks, paths = self.conf.monitor, list()
		if isinstance(masks, bytes): masks = [masks]
		for mask in masks:
			mask_patterns = self.glob_alter(mask)
			for mask_raw in mask_patterns:
				mask = FilePath(mask_raw)
				# All matched parent dirs - like /x/y/z for /x/*/z/file* - are watched for pattern
				# Note that watchers won't be auto-added for /x/m/z, if it'll be created later on
				paths_ext = list( (path.realpath(), mask.basename())
					for path in it.imap(FilePath, glob(mask.dirname())) )
				paths.extend(paths_ext)
				# If full pattern already match something, watch it if it's a dir - /x/dir1 for /x/dir*
				# Note that watchers won't be auto-added for /x/dir2, if it'll be created later on
				if paths_ext: # no point going deeper if parent dirs don't exist
					paths.extend( (path.realpath(), '*')
						for path in it.imap(FilePath, glob(mask_raw))
						if path.realpath().isdir() )
		# Aggregate path masks by-realpath
		for path, mask in paths:
			if not path.isdir():
				log.debug('Skipping special path: {}'.format(path))
				continue
			if path not in paths_watch:
				paths_watch[path] = {mask}
			else: paths_watch[path].add(mask)

		self.notifier_restart()

	def notifier_restart(self, reason=None):
		log.debug('Starting inotify watcher')
		# errback happens if some IOError gets raised in a direct callback
		self.notifier = ReliableInotify( self.paths_watch,
			ft.partial( reactor.callLater, self.conf.processing_delay,
				self.handle_change ), self.notifier_restart )


	@staticmethod
	def glob_alter(pattern, _glob_cbex = re.compile(r'\{[^}]+\}')):
		'''Shell-like glob with support for curly braces.
			Usage of these braces in the actual name isn't supported.'''
		subs = list()
		while True:
			ex = _glob_cbex.search(pattern)
			if not ex: break
			subs.append(ex.group(0)[1:-1].split(','))
			pattern = pattern[:ex.span()[0]] + '{}' + pattern[ex.span()[1]:]
		return list(it.starmap(pattern.format, it.product(*subs)))

	@staticmethod
	def file_end_mark(path, size=200, pos=None, data=None):
		if not pos:
			with path.open() as src:
				if not data:
					pos = None
					while pos != src.tell(): # to ensure that file didn't grow in-between
						pos = os.fstat(src.fileno()).st_size
						src.seek(-min(pos, size), os.SEEK_END)
						data = src.read()
				else:
					pos = os.fstat(src).st_size
		size, data = len(data), sha1(data).hexdigest()
		return pos, size, data

	@staticmethod
	def file_end_check(path, pos, size=None, data_hash=None):
		if pos != path.getsize(): return False
		elif size and data_hash:
			with path.open() as src: # lots of races ahead, but whatever
				src.seek(-size, os.SEEK_END)
				data = src.read(size)
				if len(data) != size: return False # not the end
				if sha1(data).hexdigest() != data_hash: return False # not the *same* end
		return True


	def handle_change(self, stuff, path, mask):
		mask_str = inotify.humanReadableMask(mask)
		log.noise('Event: {} ({})'.format(path, mask_str))

		## Filtering
		path_real = path.realpath()
		if not path_real.isfile():
			log.debug( 'Ignoring event for'
				' non-regular file: {} (realpath: {})'.format(path, path_real) )
			return
		dir_key = path_real.parent().realpath()
		if dir_key not in self.paths_watch:
			log.warn( 'Ignoring event for file outside of watched'
				' set of paths: {} (realpath: {})'.format(path, path_real) )
			return
		for pat in self.paths_watch[dir_key]:
			if fnmatch(bytes(path.basename()), pat): break
		else:
			log.noise( 'Non-matched path in one of'
				' the watched dirs: {} (realpath: {})'.format(path, path_real) )
			return

		## Get last position
		pos = self.paths_pos.get(path_real)
		if not pos: # try restoring it from xattr
			try: pos = pickle.loads(xattr(path_real.path)[self.conf.xattr_name])
			except KeyError:
				log.debug('Failed to restore last log position from xattr for path: {}'.format(path))
			else:
				log.noise(
					'Restored pos from xattr ({}) for path {}: {!r}'\
					.format(self.conf.xattr_name, path_real, pos) )
		if pos:
			pos, size, data_hash = pos
			if self.file_end_check(path_real, pos, size=size, data_hash=data_hash):
				log.debug(( 'Event (mask: {}) for unchanged'
					' path, ignoring: {}' ).format(mask_str, path))
				return
			if path_real.getsize() < pos:
				log.debug( 'Detected truncation'
					' of a path, rewinding: {}'.format(path) )
				pos = None

		## Actual processing
		buff_agg = self.paths_buff.setdefault(path_real, '')
		with path_real.open() as src:
			if pos:
				src.seek(pos)
				pos = None
			while True:
				pos = src.tell()
				try: buff, pos = self.read(src), src.tell()
				except StopIteration:
					buff_agg = ''
					src.seek(pos) # revert back to starting position
					buff, pos = self.read(src), src.tell()
				if not buff: # eof, try to mark the position
					if not buff_agg: # clean eof at the end of the chunk - mark it
						pos = self.file_end_mark(path_real, pos=pos, data=buff_agg)
						self.paths_pos[path_real] = pos
						xattr(path_real.path)[self.conf.xattr_name] = pickle.dumps(pos)
						log.noise( 'Updated xattr ({}) for path {} to: {!r}'\
							.format(self.conf.xattr_name, path_real, pos) )
					break
				buff_agg = self.paths_buff[path_real] = self.process(buff_agg + buff)

	def read(self, src):
		'Read however much is necessary for process() method'
		return src.readline()

	def process(self, buff):
		'Process buffered/read data, returning leftover buffer'
		if buff.endswith('\n'):
			self.handle_line(buff.strip())
			return ''
		else:
			return buff

	def handle_line(self, line):
		log.noise('New line: {!r}'.format(line))
		reactor.callLater(0, self.interface.dispatch, line, source=self)


relay = Logtail
