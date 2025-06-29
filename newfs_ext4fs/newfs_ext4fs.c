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
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include <linux/fs.h>

#include <ext4fs.h>
#include <uuid.h>

static char *progname = NULL;

void group_desc_init (struct ext4fs_group_desc *gd,
                      uint32_t block_bitmap_block,
                      uint32_t inode_bitmap_block,
                      uint32_t inode_table_start,
                      uint32_t free_blocks,
                      uint32_t free_inodes,
                      uint16_t used_dirs);

static void usage (void);

void group_desc_init (struct ext4fs_group_desc *gd,
                      uint32_t block_bitmap_block,
                      uint32_t inode_bitmap_block,
                      uint32_t inode_table_start,
                      uint32_t free_blocks,
                      uint32_t free_inodes,
                      uint16_t used_dirs)
{
  memset(gd, 0, sizeof(*gd));
  gd->gd_block_bitmap_lo = htole32(block_bitmap_block);
  gd->gd_inode_bitmap_lo = htole32(inode_bitmap_block);
  gd->gd_inode_table_lo = htole32(inode_table_start);
  gd->gd_free_blocks_count = htole16((uint16_t) (free_blocks & 0xFFFF));
  gd->gd_free_inodes_count = htole16((uint16_t) (free_inodes & 0xFFFF));
  gd->gd_used_dirs_count = htole16(used_dirs);
  gd->gd_free_blocks_count_hi = htole16((uint16_t) (free_blocks >> 16));
  gd->gd_free_inodes_count_hi = htole16((uint16_t) (free_inodes >> 16));
  gd->gd_used_dirs_count_hi = 0;
}

void parse_opt_u32 (uint32_t *dest, const char *str,
                    const char *optname)
{
  char *end = NULL;
  errno = 0;
  unsigned long val = strtoul(str, &end, 0);
  if (errno || *end != '\0' || val > UINT32_MAX) {
    fprintf(stderr, "Invalid value for -%s: '%s'\n", optname, str);
    usage();
  }
  *dest = (uint32_t) val;
}

void parse_opt_u64 (uint64_t *dest, const char *str,
                    const char *optname)
{
  char *end = NULL;
  errno = 0;
  unsigned long val = strtoul(str, &end, 0);
  if (errno || *end != '\0') {
    fprintf(stderr, "Invalid value for -%s: '%s'\n", optname, str);
    usage();
  }
  *dest = val;
}

static void usage (void) {
  fprintf(stderr,
          "Usage: %s [-b block-size] [-i bytes-per-inode]\n"
          "  [-s size-in-blocks] [-L label] [-n] [-v] [-F]\n"
          "  device\n", progname);
  exit(1);
}

int main (int argc, char **argv)
{
  uint32_t block_bitmap_block;
  uint32_t block_groups_count;
  uint32_t block_size = 4096;
  uint16_t blocks_free;
  uint32_t blocks_per_group;
  uint64_t blocks_total = 0;
  uint64_t blocks_data;
  char *buffer = NULL;
  int c;
  const char *device = NULL;
  ssize_t done;
  int fd;
  const uint32_t            gd_size = sizeof(struct ext4fs_group_desc);
  struct ext4fs_group_desc *gdt;
  uint32_t                  gdt_offset;
  uint32_t                  gdt_size;
  uint32_t inode_bitmap_block;
  uint32_t inode_ratio = 16384; // One inode per 16 KB
  uint32_t inode_size = 256;
  uint32_t inode_table_blocks;
  uint32_t inode_table_start;
  uint16_t inodes_free;
  uint32_t inodes_per_group;
  uint16_t inodes_reserved;
  uint32_t inodes_total;
  const char *label;
  time_t now;
  size_t remaining;
  uint64_t reserved_blocks;
  struct ext4fs_super_block *sb;
  uint32_t                   sb_size;
  uint64_t size;
  uint16_t used_dirs;
  ssize_t w;
  if (! argv || ! argv[0]) {
    progname = "newfs_ext4fs";
    usage();
  }
  progname = argv[0];
  while ((c = getopt(argc, argv, "b:i:s:L:nvF")) != -1) {
    switch (c) {
    case 'b':
      parse_opt_u32(&block_size, optarg, "b");
      break;
    case 'i':
      parse_opt_u32(&inode_ratio, optarg, "i");
      break;
    case 's':
      parse_opt_u64(&blocks_total, optarg, "s");
      break;
    case 'L':
      label = optarg;
      if (strlen(label) >= EXT4FS_LABEL_MAX)
        errx(1, "-L argument is too long (%d bytes max)",
             EXT4FS_LABEL_MAX);
      break;
    default: usage();
    }
  }
  if (optind >= argc) {
    fprintf(stderr, "Missing device argument.\n");
    usage();
  }
  device = argv[optind];
  fd = open(device, O_RDWR | O_EXCL);
  if (fd < 0)
    err(1, "open: %s", device);
  if (ext4fs_size(fd, &size) ||
      ! size)
    err(1, "ext4fs_size");
  printf("ext4fs_size: %lu\n", size);
  sb_size = (EXT4FS_SUPER_BLOCK_OFFSET + EXT4FS_SUPER_BLOCK_SIZE +
             (block_size - 1)) / block_size * block_size;
  buffer = calloc(1, sb_size);
  if (! buffer)
    err(1, "calloc: %d", sb_size);
  inodes_total = size / inode_ratio;
  if (! blocks_total)
    blocks_total = size / block_size;
  reserved_blocks = blocks_total / 20; // 5% reserved
  blocks_per_group = block_size * 8;
  block_groups_count = (blocks_total + (blocks_per_group - 1)) /
    blocks_per_group;
  inodes_per_group = (blocks_per_group * block_size) / inode_ratio;
  inodes_reserved = 11;
  now = time(NULL);
  sb = (struct ext4fs_super_block *) (buffer +
                                      EXT4FS_SUPER_BLOCK_OFFSET);
  sb->sb_magic = EXT4FS_MAGIC;
  sb->sb_inodes_count = htole32(inodes_total);
  sb->sb_blocks_count_lo = htole32((uint32_t)
                                   (blocks_total & 0xFFFFFFFF));
  sb->sb_blocks_count_hi = htole32((uint32_t) (blocks_total >> 32));
  sb->sb_reserved_blocks_count_lo = htole32((uint32_t)
                                            (reserved_blocks &
                                             0xFFFFFFFF));
  sb->sb_reserved_blocks_count_hi = htole32((uint32_t)
                                            (reserved_blocks >> 32));
  sb->sb_free_blocks_count_lo = htole32(blocks_total - reserved_blocks -
                                        16);
  sb->sb_free_inodes_count = htole32(inodes_total - inodes_reserved);
  sb->sb_first_data_block = htole32(block_size > 1024 ? 0 : 1);
  // log2(block_size) - 10
  sb->sb_log_block_size = htole32(__builtin_ctz(block_size) - 10);
  sb->sb_blocks_per_group = htole32(blocks_per_group);
  // assuming 1 group for now
  sb->sb_inodes_per_group = htole32(inodes_per_group);
  sb->sb_inode_size = htole16(inode_size);
  sb->sb_first_ino = htole32(inodes_reserved); // first non-reserved inode
  sb->sb_state = htole16(EXT4FS_VALID_FS);
  sb->sb_errors = htole16(EXT4FS_ERRORS_CONTINUE);
  sb->sb_rev_level = htole32(EXT4FS_DYNAMIC_REV);
  sb->sb_rev_level_minor = htole16(EXT4FS_DYNAMIC_REV_MINOR);
  sb->sb_mtime = htole32(now);
  sb->sb_wtime = htole32(now);
  sb->sb_mkfs_time = htole32(now);
  sb->sb_lastcheck = htole32(now);
  sb->sb_checkinterval = htole32(6 * 30 * 24 * 60 * 60); // 6 months
  sb->sb_feature_incompat = htole32(EXT4FS_FEATURE_INCOMPAT_EXTENTS |
                                    EXT4FS_FEATURE_INCOMPAT_64BIT);
  sb->sb_feature_ro_compat = htole32(EXT4FS_FEATURE_RO_COMPAT_SPARSE_SUPER);
  sb->sb_desc_size = htole16(gd_size);
  sb->sb_creator_os = htole32(EXT4FS_OS_OPENBSD);
  sb->sb_def_resuid = htole16(0);
  sb->sb_def_resgid = htole16(0);
  sb->sb_max_mnt_count = htole16(20);
  sb->sb_mnt_count = htole16(0);
  strncpy(sb->sb_volume_name, "ext4 disk", sizeof(sb->sb_volume_name));
  uuid_v4_gen(sb->sb_uuid);
  printf("uuid: ");
  uuid_print(sb->sb_uuid);
  sb->sb_block_group_nr = htole16(0);
  printf("\n");
  if (lseek(fd, 0, SEEK_SET) < 0)
    err(1, "lseek");
  done = 0;
  remaining = sb_size;
  while (remaining > 0) {
    w = write(fd, (char *) buffer + done, remaining);
    if (w < 0)
      err(1, "write superblock");
    done += w;
    remaining -= w;
  }
  free(buffer);
  gdt_offset = sb_size;
  gdt_size = (gd_size * block_groups_count + (block_size - 1)) /
    block_size * block_size;
  buffer = calloc(1, gdt_size);
  if (! buffer)
    err(1, "calloc: %d", gdt_size);
  block_bitmap_block = (gdt_offset + gdt_size) / block_size;
  inode_bitmap_block = block_bitmap_block + 1;
  inode_table_start = inode_bitmap_block + 1;
  inode_table_blocks = (inodes_per_group * inode_size +
                        (block_size - 1)) / block_size;
  inodes_free = inodes_total - inodes_reserved;
  blocks_data = 1;
  blocks_free = blocks_per_group -
    (2 + inode_table_blocks + blocks_data);
  used_dirs = 1;
  gdt = (struct ext4fs_group_desc *) buffer;
  group_desc_init(gdt, block_bitmap_block, inode_bitmap_block,
                  inode_table_start, blocks_free, inodes_free,
                  used_dirs);
  done = 0;
  remaining = gd_size;
  while (remaining > 0) {
    w = write(fd, (char *) buffer + done, remaining);
    if (w < 0)
      err(1, "write group descriptor");
    done += w;
    remaining -= w;
  }
  free(buffer);
  fsync(fd);
  close(fd);
  return 0;
}
