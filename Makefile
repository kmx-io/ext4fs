## ext4fs
## Copyright 2025 kmx.io <contact@kmx.io>
##
## Permission is hereby granted to use this software granted the above
## copyright notice and this permission paragraph are included in all
## copies and substantial portions of this software.
##
## THIS SOFTWARE IS PROVIDED "AS-IS" WITHOUT ANY GUARANTEE OF
## PURPOSE AND PERFORMANCE. IN NO EVENT WHATSOEVER SHALL THE
## AUTHOR BE CONSIDERED LIABLE FOR THE USE AND PERFORMANCE OF
## THIS SOFTWARE.

all: build test

build:
	${MAKE} -C crc32c_table build
	${MAKE} -C inspect_ext4fs build
	${MAKE} -C newfs_ext4fs build
	${MAKE} -C test build

clean:
	${MAKE} -C crc32c_table clean
	${MAKE} -C inspect_ext4fs clean
	${MAKE} -C newfs_ext4fs clean
	${MAKE} -C test clean

re:
	${MAKE} clean
	${MAKE} build

test: build
	${MAKE} -C test test

.PHONY: all build clean re test
