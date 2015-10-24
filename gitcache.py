#!/usr/bin/python

'''Get data out of git repositories in a way that is cacheable and concurrent.
'''
# USECASES:
# 1.  Resolving commits to trees when you have:
#     a repo url pointing to where the repository at least was at some point
#     a committish (tag or commit ideally, but may be any gitrevision)
#     a best guess as to a ref that the tree might be in.
#     If you have the repo and the committish is a fixed point:
#       Check whether that committish already exists in your cached repo.
#       Potentially: Check if any other repos have it?
#       If not found, move on.
#     TODO: Some program which speaks a subset of the git protocol to ask
#           for just the commit and trees, aborting before transferring blobs?
#     Freshly clone, or update a clone attempting:
#     1.  A shallow fetch requesting just the requested commits,
#         if the server has been configured to allow that.
#     2.  A ls-remote to see if the requested commit is the tip of any branch,
#         followed by the shallow fetch as before.
#     3.  A deep fetch of the provided branch
#     N.  Mirror everything
#     Then perform the operation locally.
# 2.  As above, but inspecting the tree to guess a build-system
#     1.  If there is a local clone with that tree, do local operations
#     2.  If the git server is recent enough, can use `git archive --remote`,
#         this can fail if the commit isn't at the tip of any of the branches,
#         and uploadArchive.allowUnreachable hasn't been set to true.
#     3.  Fall back to sparse fetch procedure and do local operations
# 3.  A faster git clone just for the specified commit,
#     plus enough history that `git describe` works,
#     given a repo url, a commit sha1 and a tree sha1.
#
#     1.  Add a smart fetch that can have the remote do the describe operation,
#         so the client can fetch just those commits.
#     2.  Repeatedly request shallow packs of all the commits for the
#         tags until it finds the target.
#     3.  Mirror all the tags.
# 4.  The cache is too large and needs to be cleaned up.
#     Set mtimes on repositories so that unused ones can be removed.
#     If you can take an exclusive lock on a repository you can prune it.
#     If auto-gc config set, take exclusive lock and don't disable autogc?
# 5.  There was a hard-crash and any state files may be wrong
#     1.  Any temporary anchor refs that aren't locked should be GC'd.
#         This should happen independently of the normal GC.
# 
# CONCURRENCY:
# Git only locks for the duration of the current operation.
# Need extra locking for some cases:
# 1.  Need to keep the commits used in a build to be anchored
#     at least as long as the build takes,
#     so after resolving the commit, it can still be cloned.
# 2.  If creating git objects in the repository,
#     or sharing the objects with another clone,
#     you need to prevent auto-gc and explicit gc for concurrent users.
#     When using the git repository, try to take a lock.
#     If you have a read-lock use git -c gc.auto=0 …
# 3.  When doing initial clone take an exclusive lock so concurrent
#     attempts to use initialising repository don't break.
#
# TODOS:
#     Features:
#     1.  Fine-grained ref locking, so you can safely run with autogc.
#         Use namespaces to separate anchor refs from cloneable refs.
#         Batch ref update into per-operation namespaces?
#     2.  Use shallow fetches
#     3.  Smarter temporary clone logic hard-linking or bind-mounting objects
#     4.  Smarter variant that keeps everything in the same git repo,
#         with namespaces for each repository
#     5.  Remote variant that connects to a proxy daemon to take locks,
#         request updates, query resolve-tree, ls-tree, cat-file, and
#         clones from a git server served from the cache.
#     6.  Chainable variant
#     Bugfixes:
#     1.  If something tries to get_repo while it's being deleted,
#         it will interpret the exclusive lock as it being set up,
#         and assume it can use it after it gets the shared lock.
#         It needs to detect that it was removed and retry.
#     Cleanup:
#     1.  Re-organise into proper module layout, separating cli from lib
#     2.  Rationalise lock timeouts to config
#     3.  Define nicer exception classes
#     Thinking:
#     1.  clone --local (default for file paths) isn't chroot safe if
#         any of the repositories have .git/objects/info/alternates.
#         Without --shared it breaks one level of dependency,
#         copying objects when it can't hardlink (explicitly or different fs).
#
#         At which point full clones must never be shared,
#         since they don't record that the objects are in use,
#         but --local is acceptable, and may optionally hardlink,
#         since you have to assume that the recursive alternates are
#         correctly handled.
#
#         At which point the only real difference for temporary clones is
#         that they manage the reference count to keep --shared or
#         --reference safe and hard-links vs bind-mounts for making it
#         chroot safe is a different problem
#
#     2.  How does this compare to git working trees?
#
#         Git working-trees are a neat, rather new feature.
#         Adding a new working tree is faster than re-cloning,
#         but its primary purpose is to let you use the same repository
#         in new and interesting ways without touching your old working tree,
#         rather than letting you quickly have multiple independent copies.

__version__ = '0.0.0'


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
		# Local fs cache should remove, 
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
	def cat_file(self, treeish, path, ref=None):
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


from contextlib import contextmanager
from cStringIO import StringIO
from datetime import datetime
from errno import EAGAIN, EEXIST
from hashlib import sha256
from itertools import chain
from os import close, devnull, listdir, rename, mkdir, mknod, stat, utime
from os.path import exists, join
from shutil import copyfileobj, rmtree
from subprocess import (call, CalledProcessError, check_call, check_output,
                        PIPE, Popen, STDOUT)
from tempfile import NamedTemporaryFile, mkdtemp

from flock import lockfile


def is_sha1(gitrevision):
	return len(gitrevision) == 40 and all(c.isalnum() for c in gitrevision)
is_fixed_revision = is_sha1


class LocalIndividualCachedGitRepository(BaseCachedGitRepository):
	'''CachedGitRepository with separate repositories indexed by name.'''
	def __init__(self, cache, repolock, gitlock, repo_url, repo_path, shared):
		self._cache = cache
		self._repolock = repolock
		self._gitlock = gitlock
		self._repo_url = repo_url
		self._repo_path = repo_path
		self._gitdir = join(repo_path, 'repo')
		self._shared = shared

	def _gitcmd(self, runner, argv, *args, **kwargs):
		if 'cwd' not in kwargs:
			kwargs['cwd'] = self._gitdir

		gitargv = ['git']
		if self._shared:
			gitargv.extend(('-c', 'gc.auto=0'))
		gitargv.extend(argv)
		return runner(gitargv, *args, **kwargs)

	@property
	def fds(self):
		return (self._repolock.fd, self._gitlock.fd)

	def get_last_used_time(self):
		st = stat(join(self._repo_path, 'timestamp'))
		time = datetime.utcfromtimestamp(st.st_mtime)
		return time.isoformat()

	def delete(self):
		utime(join(self._repo_path, 'timestamp'), None)
		# Attempt to take exclusive locks
		try:
			self._repolock.lock(timeout=0, shared=False)
			self._gitlock.lock(timeout=0, shared=False)
		except IOError as e:
			if e.errno == EAGAIN:
				# TODO: Nice error
				pass
			raise
		rmtree(self._repo_path)

	def _objects_missing(self, objects):
		p = self._gitcmd(Popen, ['cat-file', '--batch-check'],
		                 stdin=PIPE, stdout=PIPE, stderr=STDOUT)
		stdout, _ = p.communicate('\n'.join(objects))
		p.wait()
		return frozenset(
		    line.split(' ', 1)[0]
		    for line in stdout.split('\n')
		    if line and line.split(' ', 1)[1] == 'missing')

	def _update(self, commits=(), refspecs=None):
		if refspecs is not None:
			if refspecs:
				argv = ['fetch', self._repo_url]
				argv.extend('+{}:{}'.format(ref, ref)
				            for ref in refspecs)
				self._gitcmd(check_call, argv)
			if not commits or not self._objects_missing(commits):
				return
		# Fall back to fetching everything
		self._gitcmd(check_call,
		             ('fetch', self._repo_url, '+refs/*:refs/*'))
		if commits and self._objects_missing(commits):
			# TODO: Nice error
			raise Exception('commits not found')

	def update(self, commits=(), refs=None):
		utime(join(self._repo_path, 'timestamp'), None)
		if commits and not self._objects_missing(commits):
			return
		return self._update(commits=commits, refspecs=refs)

	@contextmanager
	def resolve_tree(self, treeish, refs=None):
		utime(join(self._repo_path, 'timestamp'), None)

		if self._objects_missing(objects=(treeish,)):
			self._update(commits=(treeish,), refspecs=refs)
		output = self._gitcmd(
		    check_output, ('rev-parse', treeish + '^{tree}'))
		treesha1 = output.strip()

		# TODO: Long term: Fine grained locking here by a ref namespace
		was_exclusive = not self._shared
		self._gitlock.lock(timeout=0, shared=True)
		self._shared = True
		try:
			with lockfile(self._repo_path) as templock:
				templock.lock(timeout=0, shared=True)
				yield (treesha1, (templock.fd,))
		finally:
			if was_exclusive:
				try:
					self._gitlock.lock(timeout=1, shared=False)
				except IOError as e:
					if e.errno != EAGAIN:
						raise
				else:
					self._shared = False

	def _ls_tree(self, treeish):
		# TODO: lazily evaluated version
		o = self._gitcmd(check_output,
		                 ('ls-tree', '-zr', '--name-only', treeish))
		return o[:-1].split('\0')

	def ls_tree(self, treeish, refs=()):
		utime(join(self._repo_path, 'timestamp'), None)
		if not self._objects_missing((treeish,)):
			return self._ls_tree(treeish)
		# TODO: Attempt `git archive | tar -t` before fetching ref
		if refs or refs is None:
			self._update(refspecs=refs)
		if self._objects_missing((treeish,)):
			# TODO: Nice error
			raise Exception('couldn\'t find tree')
		return self._ls_tree(treeish)

	def _cat_file(self, oid):
		# TODO: lazily evaluated version
		s = self._gitcmd(check_output, ('cat-file', 'blob', oid))
		return StringIO(s)

	def cat_file(self, treeish=None, path='.', ref=None):
		utime(join(self._repo_path, 'timestamp'), None)
		if not self._objects_missing((treeish,)):
			return self._cat_file(treeish)
		# TODO: Attempt `git archive | tar -xO` before fetching ref
		if ref is not None:
			self._update(refspecs=(ref,))
		if self._objects_missing((treeish,)):
			# TODO: Nice error
			raise Exception('couldn\'t find tree')
		return self._cat_file(treeish)

	@property
	def _hardlinks(self):
		return ('--hardlinks' if self._cache._allow_hardlinks
		                      else '--no-hardlinks')

	@staticmethod
	def _configure_ref(path, ref):
		if ref.startswith('refs/heads/'):
			remote = ('refs/remotes/origin/'
			           + ref[len('refs/heads/'):])
		else:
			remote = ref
		check_call(['git', 'config', '--add', 'remote.origin.fetch',
		            '+{}:{}'.format(ref, remote)], cwd=path)

	def _partial_clone(self, path, checkout, refs, shared):
		# Fetch just those refs (plus tags opportunistically)
		# TODO: add --shallow mode
		check_call(['git', 'init', '--quiet', path])
		check_call(['git', 'config', 'remote.origin.url',
		            self._gitdir], cwd=path)
		for ref in refs:
			self._configure_ref(path, ref)
		if shared:
			# TODO: smarter git-dir location logic
			objects = join(self._gitdir, 'objects')
			alternates = join(path, '.git', 'objects',
			                  'info', 'alternates')
			assert not exists(alternates)
			with open(alternates, 'w') as f:
				f.write(objects)
		check_call(['git', 'fetch', 'origin'], cwd=path)
		# Attempt to fetch commit into HEAD.
		# Requires uploadpack.allowTipSHA1InWant or
		# uploadpack.allowReachableSHA1InWant
		# If they aren't set the checkout will fail,
		# since fetch doesn't exit non-zero.
		if checkout and is_sha1(checkout):
			check_call(['git', 'fetch', checkout], cwd=path)

	def _is_not_tagged(self, commit):
		with open(devnull, 'w') as wnull, open(devnull, 'r') as rnull:
			returncode = self._gitcmd(
			    call, ('describe', '--contains', commit),
			    stdin=rnull, stdout=wnull, stderr=wnull)
			return returncode != 0

	def _tag_describing(self, commit):
		try:
			o = self._gitcmd(
			    check_output,
			    ('describe', '--tags', # include unannotated
			     '--long', # always include count and sha1
			     commit))
			tagname, commits, gsha1 = o.rsplit('-', 2)
			return 'refs/tags/' + tagname
		except CalledProcessError as e:
			if 'No names found' in e.output:
				return None
			raise

	def _clone(self, destination, checkout, refs,
	           describeable, shared):
		# describeable means we need to include tags.
		# We can't ever really know that the output from git-describe
		# won't change, since a more recent tag on the exact object
		# will always trump it, however retroactive tagging is unlikely
		# for projects that use git-describe, so let's stop fetching
		# tags to describe the commit when there's a tag containing it.
		# This has the side effect of performing an update when
		# requesting describeable commits when the upstream doesn't tag
		# frequently.
		# A smarter algorithm could estimate the release cycle based on
		# historic tag dates, and only fetch after the expected period,
		# and give up fetching if the last fetch is twice as long as
		# the time since the tag before the commit. But that's overkill
		if checkout and describeable and self._is_not_tagged(checkout):
			self._update(refspecs=('refs/tags/*',))
			#if self._is_not_tagged(checkout):
			#	# No tag found containing the commit,
			#	# a purist might want to abort here rather than
			#	# use an unreproducible result,
			#	pass
		# TODO: Atomic repository create
		if refs is not None:
			if checkout and describeable:
				describing_tag = self._tag_describing(checkout)
				if describing_tag is not None:
					refs = tuple(refs) + (describing_tag,)
			missing = self._objects_missing(objects=refs)
			if missing:
				self._update(refspecs=missing)
			self._update(commits=(() if checkout is None
			                         else (checkout,)),
			             refspecs=refs)
			self._partial_clone(destination, checkout, refs,
			                    shared)
		else:
			# Update all refs
			self._update()
			argv = ('clone', self._hardlinks, '--no-checkout',
			        '--shared' if shared else '--no-shared',
			        self._gitdir, destination)
			self._gitcmd(check_call, argv)
		# Set up remote
		check_call(['git', 'config', 'remote.origin.url',
		            self._repo_url], cwd=destination)
		# Check out if given
		if checkout:
			check_call(['git', 'checkout', checkout],
			           cwd=destination)

	def clone(self, destination, checkout=None, refs=(),
	          describeable=False):
		assert checkout is not None or not describeable
		utime(join(self._repo_path, 'timestamp'), None)
		return self._clone(destination=destination,
				   checkout=checkout, refs=refs,
				   describeable=describeable,
		                   shared=False)

	@contextmanager
	def clone_temporary(self, destination=None, checkout=None, refs=(),
	                    describeable=False):
		utime(join(self._repo_path, 'timestamp'), None)

		# TODO: Long term: lock a separate ref namespace and clone that
		was_exclusive = not self._shared
		self._gitlock.lock(timeout=0, shared=True)
		self._shared = True
		self._clone(destination=destination, checkout=checkout,
		            refs=refs, describeable=describeable, shared=True)
		try:
			with lockfile(self._repo_path) as templock:
				templock.lock(timeout=0, shared=True)
				yield (templock.fd,)
		finally:
			rmtree(destination, ignore_errors=True)
			if was_exclusive:
				try:
					self._gitlock.lock(timeout=1, shared=False)
				except IOError as e:
					if e.errno != EAGAIN:
						raise
				else:
					self._shared = False

class LocalIndividualGitCache(BaseGitCache):
	'''GitCache with separate repositories indexed by name.

	   The Git Cache directory contains repositories stored in directories,
	   with the basename of the directory being the sha256 has of the url.
	   This is to avoid complicated path escaping and name length rules.
	   The url of the repo is stored inside the directory.

	'''
	def __init__(self, base_directory, allow_update=True,
		     setup_timeout=1, allow_autogc=False,
		     allow_hardlinks=False, **kwargs):
		self._base_directory = base_directory
		self._allow_update = allow_update
		self._setup_timeout = setup_timeout
		self._allow_autogc = allow_autogc
		self._allow_hardlinks = allow_hardlinks

	@staticmethod
	def _init_repo(repo_url, repo_path, gitdir):
		if not exists(gitdir):
			tmpgitdir = mkdtemp(dir=repo_path)
			check_call(['git', 'init', '--bare', '--shared=all',
			            tmpgitdir])
			rename(tmpgitdir, gitdir)
		if not exists(join(repo_path, 'repo_url')):
			with NamedTemporaryFile('wb', dir=repo_path,
			                        delete=False) as f:
				f.write(repo_url)
				rename(f.name, join(repo_path, 'repo_url'))
		if not exists(join(repo_path, 'timestamp')):
			mknod(join(repo_path, 'timestamp'), 0666)

	@contextmanager
	def get_repo(self, repo_url):
		# Ensure parent directory exists
		try:
			mkdir(self._base_directory, 0755)
		except OSError as e:
			if e.errno != EEXIST:
				raise
		repo_path = join(self._base_directory,
		                 sha256(repo_url).hexdigest())
		# Make repository directory
		try:
			mkdir(repo_path, 0775)
		except OSError as e:
			if e.errno != EEXIST:
				raise
		with lockfile(repo_path) as repolock:
			# Set up repository
			try:
				repolock.lock(timeout=0, shared=False)
			except IOError as e:
				if e.errno != EAGAIN:
					raise
			else:
				self._init_repo(repo_url, repo_path,
				                join(repo_path, 'repo'))
			# Taking exclusive lock failed and Setup in progress,
			# or finished setup.
			# Either take a fresh read lock with a timeout on the
			# assumption it will be initialised soon,
			# or converts the exclusive lock to a read lock.
			try:
				repolock.lock(timeout=self._setup_timeout,
				              shared=True)
			except IOError as e:
				if e.errno == EAGAIN:
					# Timeout during setup,
					# TODO: recommend increase timeout?
					pass
				raise

			# TODO: Exclusive lock could have been taken to delete,
			#       need to retry if this was the case,
			#       and give up at some point.

			assert exists(repo_path)

			with lockfile(join(repo_path, 'repo')) as gitlock:
				shared = True
				if self._allow_autogc:
					try:
						gitlock.lock(timeout=0,
						             shared=False)
						shared = False
					except IOError as e:
						if e.errno != EAGAIN:
							raise
				# Can't auto-gc, attempt shared lock,
				# or NO-OP re-lock exclusive if we succeeded,
				# saving a bit of logic.
				try:
					gitlock.lock(timeout=0,
					             shared=shared)
				except IOError as e:
					if e.errno == EAGAIN:
						# Exclusive lock taken
						# TODO: Nice message
						pass
					raise
				yield LocalIndividualCachedGitRepository(
				    self, repolock, gitlock, repo_url,
				    repo_path, shared)

	def _cachedirs(self):
		try:
			gitdirs = listdir(self._base_directory)
		except IOError as e:
			if e.errno == ENOENT:
				return
		for gitdir in gitdirs:
			with lockfile(join(self._base_directory, gitdir)) as l:
				try:
					l.lock(timeout=1, shared=True)
				except IOError as e:
					# Skip dir if can't get lock
					if e.errno == EAGAIN:
						continue
				urlpath = join(self._base_directory,
				               gitdir, 'repo_url')
				with open(urlpath, 'r') as f:
					url = f.read()
				yield url

	def __iter__(self):
		return iter(self._cachedirs())


def load(kind='local', **kwargs):
	'''Proxy method for creating GitCaches by config.'''
	assert kind == 'local'
	return LocalIndividualGitCache(**kwargs)


# TODO: Have  a version that has a daemon sharing a local version,
#       which has an API for requesting locks

if __name__ == '__main__':
	from argparse import ArgumentParser, REMAINDER
	from select import select
	from subprocess import Popen
	from sys import stdout, stderr

	from daemon.daemon import DaemonContext
	from xdg.BaseDirectory import save_cache_path

	def _detach_and_poll(rpipe, keep_fds):
		preserve_fds = list(
		    chain(keep_fds, (rpipe,)))
		with DaemonContext(detach_process=True,
		                   files_preserve=preserve_fds):
			# Blocking drain pipe until EOF
			while True:
				select((rpipe,), (), ())
				if not rpipe.read(1024):
					break
			# Resource cleanup will happen
			# through context manager exits.

	parser = ArgumentParser(description=__doc__)
	parser.add_argument('--version', action='version',
	                    version=('%(prog)s ' + __version__))
	parser.add_argument('--base-directory', type=str,
	                    default=save_cache_path('gitcache'))
	parser.add_argument('--allow-update', type=bool, nargs='?',
	                    default=True, const=True)
	parser.add_argument('--disable-update',
	                    dest='allow_update', action='store_false')
	parser.add_argument('--setup-timeout', type=int)
	parser.add_argument('--allow-autogc', type=bool, nargs='?',
	                    default=False, const=True)
	parser.add_argument('--disable-autogc',
	                    dest='allow_autogc', action='store_false')
	parser.add_argument('--allow-hardlinks', type=bool, nargs='?',
	                    default=False, const=True)
	parser.add_argument('--disable-hardlinks',
	                    dest='allow_hardlinks', action='store_false')
	subparsers = parser.add_subparsers()

	def listrepos(options, gitcache):
		for repo_url in (options.repo_url or gitcache):
			with gitcache.get_repo(repo_url) as repo:
				stdout.write(repo_url)
				if options.display_mtime:
					stdout.write(
					    '\0' if options.null_separate
					         else '\t')
					stdout.write(repo.get_last_used_time())
				stdout.write('\0' if options.null_separate
				                  else '\n')
				stdout.flush()
	listparser = subparsers.add_parser('list')
	listparser.add_argument('repo_url', nargs='*')
	listparser.add_argument('--null', '-0', action='store_true',
	                        dest='null_separate', default=False)
	listparser.add_argument('--time', action='store_true',
	                        dest='display_mtime', default=False)
	listparser.set_defaults(func=listrepos)

	def resolvetree(options, gitcache):
		with gitcache.get_repo(options.repo_url) as repo, \
		     repo.resolve_tree(options.treeish, options.refs) as (treesha1, fds):
			print(treesha1)
			if options.read_pipe_path is not None:
				with open(options.read_pipe_path, 'r') \
				  as rpipe:
					_detach_and_poll(rpipe,
					                 chain(repo.fds, fds))
	resolvetreeparser = subparsers.add_parser('resolve-tree')
	resolvetreeparser.add_argument('repo_url')
	resolvetreeparser.add_argument('treeish', nargs='?', default='HEAD')
	resolvetreeparser.add_argument('--ref', action='append', dest='refs',
	                               metavar='REF', default=None)
	resolvetreeparser.add_argument(
	    '--read-pipe-path', metavar='FIFO', default=None,
	    help='Start a background process that will clean up repository '
	         'when the pipe is closed.')
	resolvetreeparser.set_defaults(func=resolvetree)

	def lstree(options, gitcache):
		with gitcache.get_repo(options.repo_url) as repo:
			for path in repo.ls_tree(treeish=options.treeish,
			                         refs=options.refs):
				stdout.write(path)
				stdout.write('\0' if options.null_separate
				                  else '\n')
			stdout.flush()
	lsparser = subparsers.add_parser('ls-tree')
	lsparser.add_argument('repo_url')
	lsparser.add_argument('treeish', nargs='?', default='HEAD')
	lsparser.add_argument('--ref', action='append', dest='refs', metavar='REF',
	                      default=None)
	lsparser.add_argument('--null', '-0', action='store_true',
	                      dest='null_separate', default=False)
	lsparser.set_defaults(func=lstree)

	def catfile(options, gitcache):
		with gitcache.get_repo(options.repo_url) as repo:
			copyfileobj(repo.cat_file(options.treeish,
			                          options.path), stdout)
	catparser = subparsers.add_parser('cat-file')
	catparser.add_argument('repo_url')
	catparser.add_argument('treeish', default='HEAD')
	catparser.add_argument('path')
	catparser.add_argument('--ref', action='append', dest='refs', metavar='REF',
	                       default=None)
	catparser.set_defaults(func=catfile)

	def deleterepos(options, gitcache):
		any_deleted = False
		for repo_url in options.repo_url:
			with gitcache.get_repo(repo_url) as repo:
				try:
					repo.delete()
				except IOError as e:
					if e.errno != EAGAIN:
						raise
					stderr.write(
					    'Repo {} is in use.\n'.format(
					        repo_url))
					stderr.flush()
		if not any_deleted:
			exit(1)
	deleteparser = subparsers.add_parser('delete')
	deleteparser.add_argument('repo_url', nargs='+')
	deleteparser.set_defaults(func=deleterepos)

	def clonerepo(options, gitcache):
		with gitcache.get_repo(options.repo_url) as repo:
			repo.clone(options.destination, options.checkout,
			           options.refs, options.describeable)
	cloneparser = subparsers.add_parser('clone')
	cloneparser.add_argument('repo_url')
	cloneparser.add_argument('destination')
	cloneparser.add_argument('--checkout', default=None,
	                         help='Must be a branch defined in --ref')
	cloneparser.add_argument('--ref', action='append', dest='refs', default=None)
	cloneparser.add_argument('--describeable', default=False,
	                         action='store_true')
	cloneparser.set_defaults(func=clonerepo)

	def tempclonerepo(options, gitcache):
		if options.destination is None:
			options.destination = mkdtemp()
		with gitcache.get_repo(options.repo_url) as repo, \
		     repo.clone_temporary(options.destination,
		                          options.checkout, options.refs,
			                  options.describeable) \
		                         as fds:
			if options.execute:
				def close_fds():
					for fd in chain(repo.fds, fds):
						close(fd)
				p = Popen(options.execute,
				          preexec_fn=close_fds,
				          cwd=options.destination)
				p.communicate()
				p.wait()
				exit(p.returncode)
			elif options.read_pipe_path:
				with open(options.read_pipe_path, 'r') \
				  as rpipe:
					_detach_and_poll(rpipe,
					                 chain(repo.fds, fds))
			else:
				assert False
	tempcloneparser = subparsers.add_parser('clone-temporary')
	tempcloneparser.add_argument('repo_url')
	tempcloneparser.add_argument('destination', nargs='?')
	tempcloneparser.add_argument('--checkout', default=None,
	                             help='Must be a branch defined in --ref')
	tempcloneparser.add_argument('--ref', action='append', dest='refs',
	                             metavar='REF', default=None)
	tempcloneparser.add_argument('--describeable', default=False,
	                             action='store_true')
	group = tempcloneparser.add_mutually_exclusive_group(required=True)
	group.add_argument(
	    '--read-pipe-path', metavar='FIFO',
	    help='Start a background process that will clean up repository '
	         'when the pipe is closed.')
	group.add_argument(
	    '--execute', '-x', nargs=REMAINDER, default=(), metavar='ARGV',
	    help='Run %(metavar)s inside the repository and clean up on exit.')
	tempcloneparser.set_defaults(func=tempclonerepo)

	options = parser.parse_args()
	gitcache = load(**vars(options))
	options.func(options, gitcache)
