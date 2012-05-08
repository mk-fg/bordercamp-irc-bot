# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
from fnmatch import fnmatch
from hashlib import sha1
from io import open
import os, sys, re, pickle

from xattr import xattr

from twisted.python.filepath import FilePath
from twisted.internet import inotify, reactor, defer
from twisted.python import log

from . import BCRelay


class Logtail(BCRelay):


	def __init__(self, *argz, **kwz):
		super(Logtail, self).__init__(*argz, **kwz)

		self.paths_pos = dict()
		self.paths_watch = dict()
		self.paths_buff = dict()

		self.notifier = inotify.INotify()
		self.notifier.startReading()

		masks = self.conf.monitor
		if isinstance(masks, bytes): masks = [masks]
		for mask in masks: self.monitor(mask)


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

	@staticmethod
	def glob(pattern, _glob_cbex = re.compile(r'\{[^}]+\}')):
		'''Shell-like glob with support for curly braces.
			Usage of these braces in the actual name isn't supported.'''
		subs = list()
		while True:
			ex = _glob_cbex.search(pattern)
			if not ex: break
			subs.append(ex.group(0)[1:-1].split(','))
			pattern = pattern[:ex.span()[0]] + '{}' + pattern[ex.span()[1]:]
		return list(it.chain.from_iterable(
				glob(pattern.format(*combo))
				for combo in it.product(*subs) ))\
			if subs else glob(pattern)


	def monitor(self, path_mask):
		paths_watch, paths = self.paths_watch, self.glob(path_mask)
		for path in it.imap(FilePath, paths):
			path_real = path.realpath()
			# Matched regular files are watched as a basename pattern in the dir
			if path_real.isfile():
				path_dir = path.parent().realpath()
				if path_dir not in paths_watch:
					paths_watch[path_dir] = {path.basename()}
				else: paths_watch[path_dir].add(path.basename())
			# All files in the matched dirs are watched, non-recursively
			elif path_real.isdir():
				if path_real not in paths_watch: paths_watch[path_real] = {'*'}
				else: paths_watch[path_real].add('*')
				for name in path_real.listdir():
					path_child = path_real.child(name).realpath()
			# Specials of any kind are ignored
			else: log.debug('Skipping non-file/dir path: {}'.format(path_real))
		for path in paths_watch:
			log.debug('Adding watcher for path: {}'.format(path))
			self.notifier.watch( path,
				mask=inotify.IN_CREATE | inotify.IN_MODIFY,
				callbacks=[self.handle_change] )


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
		line = self.paths_buff.setdefault(path_real, '')
		with path_real.open('rb') as src:
			if pos:
				src.seek(pos)
				pos = None
			while True:
				buff, pos = src.readline(), src.tell()
				if not buff: # eof, try to mark the position
					if not line: # clean eof at the end of the line - mark it
						pos = self.file_end_mark(path_real, pos=pos, data=line)
						self.paths_pos[path_real] = pos
						xattr(path_real.path)[self.conf.xattr_name] = pickle.dumps(pos)
						log.noise( 'Updated xattr ({}) for path {} to: {!r}'\
							.format(self.conf.xattr_name, path_real, pos) )
					break
				line += buff
				if line.endswith('\n'):
					log.noise('New line (source: {}): {!r}'.format(path, line))
					reactor.callLater(0, self.handle_line, line)
					line = self.paths_buff[path_real] = ''
				else:
					line, self.paths_buff[path_real] = None, line
					break


	def handle_line(self, line):
		self.interface.dispatch(line.strip(), source=self)


relay = Logtail
