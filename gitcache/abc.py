#!/usr/bin/python


from __future__ import absolute_import


__all__ = ('BaseGitCache', 'BaseCachedGitRepository')


from abc import ABCMeta, abstractmethod, abstractproperty


# TODO: Python3 compatibility or remove entirely,
# since python is duck typed so this is just a development assertion
class BaseCachedGitRepository(object):
	__metaclass__ = ABCMeta
	@abstractproperty
	def fds(self):
		'''Iterable of file descriptors used.

		   Due to global state file descriptors can't safely
		   be implementation details, so this property includes
		   any file descriptors used by the CachedGitRepository.

		   This may be used to ensure these files aren't passed
		   to subprocesses that can't be trusted with them,
		   and can be passed to subprocesses that should take
		   ownership of cleanup.
		'''
		return ()
	@abstractmethod
	def get_last_used_time(self):
		'Return last used time as UTC date string.'
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def delete(self):
		'Declare that we no longer wish to use resources caching this'
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def update(
		self,
		# Committishes that if resolvable mean we don't need to fetch.
		commits=(),
		# Refs that we should try fetching before mirroring everything.
		refs=()):
		'''This ensures all given commits are resolvable,
		   (though if no commits are specified it should fetch refs)
		   by checking locally if the commits exist first,
		   if they don't it should try again after fetching `refs`,
		   and if that doesn't work it should mirror everything.
		'''
		raise NotImplementedError("Subclasses should implement this!")
	# TODO: Should resolve_tree return an object with ls_tree and cat_file?
	@abstractmethod
	def resolve_tree(self, treeish, ref=None):
		'''Context manager yielding a resolved tree and anchor fds

		   The context ensures the commit the tree was reached
		   by is anchored in a manner that is concurrency safe.

		   This ensures that the tree isn't gc'd when in use,
		   so later ls_tree, cat_file or clone don't have to re-fetch,
		   and you can't fail because you relied on a removed commit.
		'''
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def ls_tree(self, treeish, ref=None):
		'''List files recursively by treeish.

		   Returns an iterable of file paths.
		'''
		# git archive --remote=$repo_url $TREEISH | tar -t
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def cat_file(self, treeish, path, refs=()):
		'''Read file by treeish and path.

		   Returns a file-like object of the file's contents.
		'''
		# git archive --remote=$repo_url $treeish $path | tar -xO $path
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def clone(self, path, checkout=None, refs=(), describeable=False):
		'''Make a local clone available.

		   `checkout` may be None if that should be deferred,
		   otherwise it should be a committish.
		   If `describeable` the closest tag before is included.
		   `refs` may be empty if only the checkout is required.

		'''
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def clone_temporary(self, path, checkout=None, refs=(),
	                    describeable=False):
		'''Context manager for making temporary clones.

		   Behaves like clone(), but removes it on scope exit.
		   This allows optimisations for creating it.

		   Yields an iterable of file descriptors used.

		   Cleans up used resources on scope exit.
		'''
		# 1.  Try CoW clone.
		# 2.  Try to hard-link objects alongside the target
		#     Set up alternates and yield the directory containing
		#     hard-linked objects, so that the user can take steps to
		#     ensure it won't be modified.
		# 3.  Try to bind-mount-ro objects alongside the target,
		#     taking a read-lock on the cached repository,
		#     relesasing and unmounting on scope exit.
		raise NotImplementedError("Subclasses should implement this!")


class BaseGitCache(object):
	__metaclass__ = ABCMeta
	@abstractmethod
	def get_repo(self, repo_url):
		'''Context manager yielding a CachedGitRepository

		   This returns an unfetched repository proxy.
		   
		'''
		# NOTE: Should init with --shared=all so objects shareable
		raise NotImplementedError("Subclasses should implement this!")
	@abstractmethod
	def __iter__(self):
		'''Iterator for all repo urls that are cached.'''
		raise NotImplementedError("Subclasses should implement this!")
