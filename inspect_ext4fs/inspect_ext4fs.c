/* ext4fs
 * Copyright 2025 kmx.io <contact@kmx.io>
 *
 * Permission is hereby granted to use this software granted the above
 * copyright notice and this permission paragraph are included in all
 * copies and substantial portions of this software.
 *
 * THIS SOFTWARE IS PROVIDED "AS-IS" WITHOUT ANY GUARANTEE OF
 * PURPOSE AND PERFORMANCE. IN NO EVENT WHATSOEVER SHALL THE
 * AUTHOR BE CONSIDERED LIABLE FOR THE USE AND PERFORMANCE OF
 * THIS SOFTWARE.
 */
#define _DEFAULT_SOURCE 1
#include <endian.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <linux/fs.h>

#include <ext4fs.h>
#include <uuid.h>

int main (int argc, char **argv)
{
  int fd;
  if (argc != 2 || ! argv)
    errx(1, "invalid arguments");
  printf("%s %s\n", argv[0], argv[1]);
  fd = open(argv[1], O_RDONLY | O_EXCL);
  if (fd < 0)
    err(1, "open: %s", argv[1]);
  if (ext4fs_inspect(fd)) {
    close(fd);
    return 1;
  }
  close(fd);
  return 0;
}
