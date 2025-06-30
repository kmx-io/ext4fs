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

include configure.mk

PROG =    inspect_ext4fs
HEADERS = ../include/ext4fs.h ../include/uuid.h
SOURCES = inspect_ext4fs.c ext4fs.c uuid.c
OBJECTS = inspect_ext4fs.o ext4fs.o uuid.o

CPPFLAGS = -I../include -D${UNAME}
CFLAGS = -W -Wall -Werror -O0 -g -pedantic -std=c11

all: build

build: ${PROG}

${OBJECTS}: ${HEADERS}

${PROG}: ${OBJECTS}
	${CC} ${CFLAGS} ${LDFLAGS} ${OBJECTS} -o ${PROG}

.PHONY: all build
