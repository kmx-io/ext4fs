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
#include <stdio.h>

#include <ext4fs.h>

long g_test_ko = 0;
long g_test_ok = 0;
long g_test_total = 0;

#define TEST_ASSERT(test)                         \
  do {                                            \
    if (! (test)) {                               \
      fprintf(stderr, "KO: %s\n", # test);        \
      g_test_ko++;                                \
      g_test_total++;                             \
    }                                             \
    else {                                        \
      g_test_ok++;                                \
      g_test_total++;                             \
    }                                             \
  } while (0)

void test_summary (void)
{
  fflush(stdout);
  fprintf(stderr, "OK: %ld\tKO: %ld\tTotal: %ld\n",
          g_test_ok, g_test_ko, g_test_total);
  fflush(stderr);
}

int main (int argc, char **argv)
{
  (void) argc;
  (void) argv;
  TEST_ASSERT(sizeof(struct ext4fs_super_block) == 1024);
  TEST_ASSERT(sizeof(struct ext4fs_group_desc) == 64);
  test_summary();
  return 0;
}
