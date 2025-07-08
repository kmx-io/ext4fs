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
#include <string.h>
#include <strings.h>

#include <ext4fs.h>
#include <crc32c.h>
#include <uuid.h>

long g_test_ko = 0;
long g_test_ok = 0;
long g_test_total = 0;

#define TEST_ASSERT(test)                                              \
  do {                                                                 \
    if (! (test)) {                                                    \
      fprintf(stderr, "KO: %s\n", # test);                             \
      g_test_ko++;                                                     \
      g_test_total++;                                                  \
    }                                                                  \
    else {                                                             \
      g_test_ok++;                                                     \
      g_test_total++;                                                  \
    }                                                                  \
  } while (0)

#define TEST_EQ(test, expected)                                        \
  do {                                                                 \
    int64_t i_test = (test);                                           \
    int64_t i_expected = (expected);                                   \
    if (! ((i_test) == (i_expected))) {                                \
      fprintf(stderr, "KO: expected %s == %ld, got %ld instead\n",   \
              # test, i_expected, i_test);                             \
      g_test_ko++;                                                     \
      g_test_total++;                                                  \
    }                                                                  \
    else {                                                             \
      g_test_ok++;                                                     \
      g_test_total++;                                                  \
    }                                                                  \
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
  uint8_t b[32];
  uint32_t u32;
  (void) argc;
  (void) argv;
  TEST_EQ(offsetof(struct ext4fs_super_block, sb_default_mount_opts),
          0x100);
  TEST_EQ(offsetof(struct ext4fs_super_block, sb_mount_opts),
          0x200);
  TEST_EQ(offsetof(struct ext4fs_super_block, sb_orphan_file_inode),
          0x280);
  TEST_EQ(offsetof(struct ext4fs_super_block, sb_checksum),
          0x3FC);
  TEST_EQ(sizeof(struct ext4fs_super_block),
          1024);
  TEST_EQ(sizeof(struct ext4fs_block_group_descriptor),
          64);
  u32 = 0;
  TEST_EQ(crc32c(0, &u32, 4), 0x48674BC7);
  bzero(b, sizeof(b));
  TEST_EQ(crc32c(0, b, sizeof(b)), 0x8A9136AAU);
  memset(b, -1, sizeof(b));
  TEST_EQ(crc32c(0, b, sizeof(b)), 0x62A8AB43U);
  TEST_EQ(crc32c(0, "123456789", 9), 0xE3069283U);
  test_summary();
  return 0;
}
