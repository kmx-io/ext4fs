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

PROG =    crc32c_table
HEADERS =
SOURCES = crc32c_table.c
OBJECTS = crc32c_table.o
OUT_H =   crc32c_table.h

CPPFLAGS = -I../include
CFLAGS = -W -Wall -Werror -O0 -g -pedantic -std=c11

all: build gen

build: ${PROG}

gen: build
	./${PROG} > ${OUT_H}

${OBJECTS}: ${HEADERS}

${PROG}: ${OBJECTS}
	${CC} ${CFLAGS} ${LDFLAGS} ${OBJECTS} -o ${PROG}

test: build
	./${PROG}

.PHONY: all build test
