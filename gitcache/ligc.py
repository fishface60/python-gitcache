#!/usr/bin/python


__all__ = ('LocalIndividualCoarseGitCache',)


from contextlib import contextmanager
from cStringIO import StringIO
from datetime import datetime
from errno import EAGAIN, EEXIST
from hashlib import sha256
from os import devnull, listdir, rename, mkdir, mknod, stat, utime
from os.path import exists, join
from shutil import rmtree
from subprocess import (call, CalledProcessError, check_call, check_output,
                        PIPE, Popen, STDOUT)
from tempfile import NamedTemporaryFile, mkdtemp

from flock import lockfile

from .abc import BaseGitCache, BaseCachedGitRepository
from .util import is_sha1, is_fixed_revision


class LocalIndividualCoarseCachedGitRepository(BaseCachedGitRepository):
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
		'''Run git subprocesses the right way.

		When we have a shared lock we need to disable autogc,
		but we don't want to have to modify the repository config,
		so the nicest way to do this is run with -c gc.auto=0.

		'''
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

	def cat_file(self, treeish, path=None, refs=()):
		utime(join(self._repo_path, 'timestamp'), None)
		if not self._objects_missing((treeish,)):
			if path is None:
				return self._cat_file(treeish)
			else:
				return self._cat_file(
				    '{treeish}:{path}'.format(
				        treeish=treeish, path=path))
		# TODO: Attempt `git archive | tar -xO` before fetching ref
		self._update(refspecs=(ref,))
		if self._objects_missing((treeish,)):
			# TODO: Nice error
			raise Exception('couldn\'t find tree')
		if path is None:
			return self._cat_file(treeish)
		else:
			return self._cat_file('{treeish}:{path}'.format(
			    treeish=treeish, path=path))

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
		# TODO: add shallow mode
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

class LocalIndividualCoarseGitCache(BaseGitCache):
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
				yield LocalIndividualCoarseCachedGitRepository(
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
