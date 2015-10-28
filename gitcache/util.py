#!/usr/bin/python


def is_sha1(gitrevision):
	'''Check whether `gitrevision` string is a sha1 digest.'''
	return len(gitrevision) == 40 and all(c.isalnum() for c in gitrevision)


def is_fixed_revision(gitrevision):
	'''Check whether `gitrevision` would always resolve the same.'''
	# TODO: sha1^{tree} is also a fixed revision
	return is_sha1(gitrevision)
