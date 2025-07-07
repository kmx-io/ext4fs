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
SOURCES = crc32c.c inspect_ext4fs.c ext4fs.c uuid.c
OBJECTS = crc32c.o inspect_ext4fs.o ext4fs.o uuid.o

HEADERS =	../crc32c_table/crc32c_table.h \
		../include/crc32c.h \
		../include/ext4fs.h \
		../include/uuid.h

CPPFLAGS = -I../include -D${UNAME}
CFLAGS = -W -Wall -Werror -O0 -g -pedantic -std=c11

all: build

build: ${PROG}

crc32c.o: ../crc32c.c

ext4fs.o: ../ext4fs.c

uuid.o: ../uuid.c

${OBJECTS}: ${HEADERS} Makefile

${PROG}: ${OBJECTS}
	${CC} ${CFLAGS} ${LDFLAGS} ${OBJECTS} -o ${PROG}

.PHONY: all build
