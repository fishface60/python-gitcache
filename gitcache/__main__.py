#!/usr/bin/python

'''CLI for performing git operations with a cache.'''


from argparse import ArgumentParser, REMAINDER
from errno import EAGAIN
from itertools import chain
from os import close
from select import select
from shutil import copyfileobj
from subprocess import Popen
from sys import stdout, stderr
from tempfile import mkdtemp

from daemon.daemon import DaemonContext
from xdg.BaseDirectory import save_cache_path

from gitcache import load, __version__

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

parser = ArgumentParser(description=__doc__, prog=__package__)
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
		                          options.path, options.refs), stdout)
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
