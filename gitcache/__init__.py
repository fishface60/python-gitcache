#!/usr/bin/python

from __future__ import absolute_import

'''Get data out of git repositories in a way that is cacheable and concurrent.
'''


__all__ = ('__version__', 'load')


__version__ = '0.0.0'


from . import ligc


def load(kind='local-individual-coarse', **kwargs):
	'''Proxy method for creating GitCaches by config.'''
	assert kind == 'local-individual-coarse'
	return ligc.LocalIndividualCoarseGitCache(**kwargs)
