#!/usr/bin/env python

import itertools as it, operator as op, functools as ft
from glob import iglob
import os, sys

from setuptools import setup, find_packages

pkg_root = os.path.dirname(__file__)

setup(

	name = 'bordercamp-irc-bot',
	version = '12.5.5',
	author = 'Mike Kazantsev',
	author_email = 'mk.fraggod@gmail.com',
	license = 'WTFPL',
	keywords = 'irc notification bot chat logs',
	url = 'http://github.com/mk-fg/bordercamp-irc-bot',

	description = 'IRC notification bot',
	long_description = open(os.path.join(pkg_root, 'README.md')).read(),

	classifiers = [
		'Development Status :: 4 - Beta',
		'Environment :: No Input/Output (Daemon)',
		'Environment :: Other Environment',
		'Framework :: Twisted',
		'Intended Audience :: Developers',
		'Intended Audience :: Information Technology',
		'Intended Audience :: System Administrators',
		'Intended Audience :: Telecommunications Industry',
		'License :: OSI Approved',
		'Natural Language :: English',
		'Operating System :: POSIX',
		'Operating System :: Unix',
		'Programming Language :: Python',
		'Programming Language :: Python :: 2.7',
		'Programming Language :: Python :: 2 :: Only',
		'Topic :: Communications :: Chat :: Internet Relay Chat'
		'Topic :: Internet',
		'Topic :: System :: Networking :: Monitoring',
		'Topic :: System :: Systems Administration' ],

	install_requires = ['Twisted-Core', 'Twisted-Words', 'PyYAML', 'setuptools'],

	packages = find_packages(),
	include_package_data = True,

	package_data = {'bordercamp': ['core.yaml']},
	entry_points = {
		'console_scripts': ['bordercamp = bordercamp.core:main'],
		'bordercamp.relays': list(
			'{0} = bordercamp.relays.{0}'.format(name[:-3])
			for name in it.imap(os.path.basename, iglob(os.path.join(
						pkg_root, 'bordercamp', 'relays', '[!_]*.py' ))) ) } )
