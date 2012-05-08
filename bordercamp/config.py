# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from collections import Mapping, OrderedDict
import os, sys
import yaml, yaml.constructor


class OrderedDictYAMLLoader(yaml.Loader):
	'Based on: https://gist.github.com/844388'

	def __init__(self, *args, **kwargs):
		yaml.Loader.__init__(self, *args, **kwargs)
		self.add_constructor(u'tag:yaml.org,2002:map', type(self).construct_yaml_map)
		self.add_constructor(u'tag:yaml.org,2002:omap', type(self).construct_yaml_map)

	def construct_yaml_map(self, node):
		data = OrderedDict()
		yield data
		value = self.construct_mapping(node)
		data.update(value)

	def construct_mapping(self, node, deep=False):
		if isinstance(node, yaml.MappingNode):
			self.flatten_mapping(node)
		else:
			raise yaml.constructor.ConstructorError( None, None,
				'expected a mapping node, but found {}'.format(node.id), node.start_mark )

		mapping = OrderedDict()
		for key_node, value_node in node.value:
			key = self.construct_object(key_node, deep=deep)
			try:
				hash(key)
			except TypeError, exc:
				raise yaml.constructor.ConstructorError( 'while constructing a mapping',
					node.start_mark, 'found unacceptable key ({})'.format(exc), key_node.start_mark )
			value = self.construct_object(value_node, deep=deep)
			mapping[key] = value
		return mapping


class AttrDict(dict):

	def __init__(self, *argz, **kwz):
		for k,v in dict(*argz, **kwz).iteritems(): self[k] = v

	def __setitem__(self, k, v):
		super(AttrDict, self).__setitem__( k,
			AttrDict(v) if isinstance(v, Mapping) else v )
	def __getattr__(self, k):
		if not k.startswith('__'): return self[k]
		else: raise AttributeError # necessary for stuff like __deepcopy__ or __hash__
	def __setattr__(self, k, v): self[k] = v

	@classmethod
	def from_yaml(cls, path, if_exists=False):
		import yaml
		if if_exists and not os.path.exists(path): return cls()
		return cls(yaml.load(open(path), OrderedDictYAMLLoader))

	@staticmethod
	def flatten_dict(data, path=tuple()):
		dst = list()
		for k,v in data.iteritems():
			k = path + (k,)
			if isinstance(v, Mapping):
				for v in v.flatten(k): dst.append(v)
			else: dst.append((k, v))
		return dst

	def flatten(self, path=tuple()):
		return self.flatten_dict(self, path=path)

	def update_flat(self, val):
		if isinstance(val, AttrDict): val = val.flatten()
		for k,v in val:
			dst = self
			for slug in k[:-1]:
				if dst.get(slug) is None:
					dst[slug] = AttrDict()
				dst = dst[slug]
			if v is not None or not isinstance(
				dst.get(k[-1]), Mapping ): dst[k[-1]] = v

	def update_dict(self, data):
		self.update_flat(self.flatten_dict(data))

	def update_yaml(self, path):
		self.update_flat(self.from_yaml(path))

	def clone(self):
		clone = AttrDict()
		clone.update_dict(self)
		return clone

	def rebase(self, base):
		base = base.clone()
		base.update_dict(self)
		self.clear()
		self.update_dict(base)


def configure_logging(cfg, custom_level=None):
	import logging, logging.config
	if custom_level is None: custom_level = logging.WARNING
	for entity in it.chain.from_iterable(it.imap(
			op.methodcaller('viewvalues'),
			[cfg] + list(cfg.get(k, dict()) for k in ['handlers', 'loggers']) )):
		if isinstance(entity, Mapping)\
			and entity.get('level') == 'custom': entity['level'] = custom_level
	logging.config.dictConfig(cfg)
	logging.captureWarnings(cfg.warnings)


def ep_config(cfg, ep_specs):
	# ep_specs = [{ ep='relays',
	#  enabled=[ep_name, ...], disabled=[ep_name, ...] }, ...]
	ep_conf = dict()
	for spec in ep_specs:
		ep = spec['ep']
		conf = cfg[ep]
		conf_base = conf.pop('_default')
		enabled = spec.get('enabled', list())
		if enabled:
			for name, subconf in conf.viewitems():
				if name not in enabled: subconf['enabled'] = False
			for name in enabled:
				if name not in conf: conf[name] = dict()
				conf[name]['enabled'] = True
		disabled = spec.get('disabled', list())
		for name in disabled:
			if name not in conf: conf[name] = dict()
			conf[name]['enabled'] = False
		if 'debug' not in conf_base: conf_base['debug'] = cfg.debug
		ep_conf[ep] = conf_base, conf
	return ep_conf
