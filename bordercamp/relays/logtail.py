# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from glob import glob
from fnmatch import fnmatch
from hashlib import sha1
from io import open
import os, sys, re

from twisted.python.filepath import FilePath
from twisted.internet import inotify, reactor, defer
from twisted.python import log

from . import BCRelay


class Logtail(BCRelay):

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
	def file_end_check(path, pos, size=None, data=None):
		if pos != path.getsize(): return False
		elif size and data:
			with path.open() as src:
				src.seek(-size, os.SEEK_END)
				if sha1(src.read()).hexdigest() != data: return False
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
		return it.chain.from_iterable(
				glob(pattern.format(*combo))
				for combo in product(*subs) )\
			if subs else glob(pattern)


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


	def monitor(self, path_mask):
		paths_pos = self.paths_pos
		paths_watch = self.paths_watch
		paths = glob(path_mask)
		for path in it.imap(FilePath, paths):
			path_real = path.realpath()
			# Matched regular files are watched as a basename pattern in the dir
			if path_real.isfile():
				path_dir = path.parent().realpath()
				if path_dir not in paths_watch:
					paths_watch[path_dir] = {os.path.basename(optz.path_mask)}
				else: paths_watch[path_dir].add(os.path.basename(optz.path_mask))
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
		if self.paths_pos.get(path_real) is not None:
			pos, size, data = self.paths_pos[path_real]
			if self.file_end_check(path_real, pos, size=size, data=data):
				log.debug(( 'Event (mask: {}) for unchanged'
					' path, ignoring: {}' ).format(mask_str, path))
				return
			if path_real.getsize() < pos:
				log.debug( 'Detected truncation'
					' of a path, rewinding: {}'.format(path) )
				pos = None
		else: pos = None

		## Actual processing
		line = self.paths_buff.setdefault(path_real, '')
		with path_real.open('rb') as src:
			if pos:
				src.seek(pos)
				pos = None
			while True:
				buff = src.readline()
				if not buff: # eof
					self.paths_pos[path_real] = self.file_end_mark(path_real, data=line)
				line += buff
				if line.endswith('\n'):
					log.noise('New line (source: {}): {!r}'.format(path, line))
					reactor.callLater(0, self.handle_line, line)
					line = self.paths_buff[path_real] = ''
				else:
					line, self.paths_buff[path_real] = None, line
					break


	# @defer.inlineCallbacks
	def handle_line(self, line):
		log.debug('Yay for line: {}'.format(line))


relay = Logtail
