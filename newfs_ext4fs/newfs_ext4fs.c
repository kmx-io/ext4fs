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
#include "configure.h"

#define _DEFAULT_SOURCE 1

#ifdef Linux
# include <linux/fs.h>
#endif

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

#include <ext4fs.h>
#include <uuid.h>

static char *progname = NULL;

void arc4random_buf(void *buf, size_t n);

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
  uint16_t block_group_id = 0;
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
  uint32_t groups_per_flex = 16;
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
  uint16_t reserved_gdt_blocks = 1024;
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
      if (strlen(label) >= EXT4FS_VOLUME_NAME_MAX)
        errx(1, "-L argument is too long (%d bytes max)",
             EXT4FS_VOLUME_NAME_MAX);
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
  if (ext4fs_size(device, fd, &size) ||
      ! size)
    errx(1, "ext4fs_size: %s", device);
  printf("ext4fs_size: " CONFIGURE_FMT_UINT64 "\n", size);
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
  sb->sb_log_cluster_size = sb->sb_log_block_size;
  sb->sb_blocks_per_group = htole32(blocks_per_group);
  sb->sb_clusters_per_group = sb->sb_blocks_per_group;
  sb->sb_inodes_per_group = htole32(inodes_per_group);
  sb->sb_mount_time_lo = htole32(now);
  sb->sb_mount_time_hi = (now >> 32) & 0xFF;
  sb->sb_write_time_lo = htole32(now);
  sb->sb_write_time_hi = (now >> 32) & 0xFF;
  sb->sb_mount_count = htole16(0);
  sb->sb_max_mount_count_before_fsck = (int16_t) htole16(-1);
  sb->sb_magic = htole16(EXT4FS_MAGIC);
  sb->sb_state = htole16(EXT4FS_STATE_VALID);
  sb->sb_errors = htole16(EXT4FS_ERRORS_CONTINUE);
  sb->sb_revision_level_minor = htole16(EXT4FS_REV_MINOR);
  sb->sb_check_time_lo = htole32(now);
  sb->sb_check_time_hi = (now >> 32) & 0xFF;
  sb->sb_check_interval = htole32(6 * 30 * 24 * 60 * 60); // 6 months
  sb->sb_creator_os = htole32(EXT4FS_OS_OPENBSD);
  sb->sb_revision_level = htole32(EXT4FS_REV_DYNAMIC);
  sb->sb_default_reserved_uid = htole16(0);
  sb->sb_default_reserved_gid = htole16(0);
  sb->sb_first_non_reserved_inode = htole32(inodes_reserved); // first non-reserved inode
  sb->sb_inode_size = htole16(inode_size);
  sb->sb_block_group_id = htole16(block_group_id);
  sb->sb_feature_compat = htole32(0);
  sb->sb_feature_incompat = htole32(EXT4FS_FEATURE_INCOMPAT_EXTENTS |
                                    EXT4FS_FEATURE_INCOMPAT_64BIT);
  sb->sb_feature_ro_compat = htole32(EXT4FS_FEATURE_RO_COMPAT_SPARSE_SUPER);
  uuid_v4_gen(sb->sb_uuid);
  strncpy(sb->sb_volume_name, "ext4fs test", sizeof(sb->sb_volume_name));
  bzero(sb->sb_last_mounted, EXT4FS_LAST_MOUNTED_MAX);
  sb->sb_algorithm_usage_bitmap = htole32(0);
  sb->sb_preallocate_blocks = 0;
  sb->sb_preallocate_dir_blocks = 0;
  sb->sb_reserved_gdt_blocks = htole16(reserved_gdt_blocks);
  bzero(sb->sb_journal_uuid, sizeof(sb->sb_journal_uuid));
  sb->sb_journal_inode_number = htole32(0);
  sb->sb_journal_device_number = htole32(0);
  sb->sb_last_orphan = htole32(0);
  bzero(sb->sb_hash_seed, sizeof(sb->sb_hash_seed));
  sb->sb_default_hash_version = 0;
  sb->sb_journal_backup_type = 0;
  sb->sb_group_descriptor_size = htole16(gd_size);
  sb->sb_default_mount_opts = htole32(0);
  sb->sb_first_meta_block_group = htole32(0);
  sb->sb_newfs_time_lo = htole32(now);
  sb->sb_newfs_time_hi = (now >> 32) & 0xFF;
  bzero(sb->sb_jnl_blocks, sizeof(sb->sb_jnl_blocks));
  sb->sb_inode_size_extra_min = htole16(32);
  sb->sb_inode_size_extra_want = htole16(32);
  sb->sb_flags = htole32(0);
  sb->sb_raid_stride_block_count = htole16(0);
  sb->sb_mmp_interval = 0;
  sb->sb_mmp_block = 0;
  sb->sb_raid_stripe_width_block_count = htole32(0);
  sb->sb_log_groups_per_flex = __builtin_ctz(groups_per_flex);
  sb->sb_checksum_type = 0;
  sb->sb_reserved_176 = 0;
  sb->sb_kilobytes_written = htole64(0);
  sb->sb_ext3_snapshot_inum = 0;
  sb->sb_ext3_snapshot_id = 0;
  sb->sb_ext3_snapshot_reserved_blocks_count = 0;
  sb->sb_ext3_snapshot_list = 0;
  sb->sb_error_count = 0;
  sb->sb_first_error_time_lo = 0;
  sb->sb_first_error_time_hi = 0;
  sb->sb_first_error_inode = 0;
  sb->sb_first_error_block = 0;
  bzero(sb->sb_first_error_function, EXT4FS_FUNCTION_MAX);
  sb->sb_first_error_line = 0;
  sb->sb_last_error_time_lo = 0;
  sb->sb_last_error_time_hi = 0;
  sb->sb_last_error_inode = 0;
  sb->sb_last_error_line = 0;
  sb->sb_last_error_block = 0;
  bzero(sb->sb_last_error_function, EXT4FS_FUNCTION_MAX);
  bzero(sb->sb_mount_opts, sizeof(sb->sb_mount_opts));
  sb->sb_user_quota_inum = 0;
  sb->sb_group_quota_inum = 0;
  sb->sb_overhead_clusters = 0;
  sb->sb_backup_bgs[0] = 0;
  sb->sb_backup_bgs[1] = 0;
  bzero(sb->sb_encrypt_algos, sizeof(sb->sb_encrypt_algos));
  bzero(sb->sb_encrypt_pw_salt, sizeof(sb->sb_encrypt_pw_salt));
  sb->sb_lost_and_found_inode = htole32(0);
  sb->sb_project_quota_inum = htole32(0);
  sb->sb_checksum_seed = htole32(0);
  sb->sb_first_error_code = 0;
  sb->sb_last_error_code = 0;
  sb->sb_encoding = htole16(EXT4FS_ENCODING_UTF8);
  sb->sb_encoding_flags = htole16(EXT4FS_ENCODING_FLAG_STRICT_MODE);

  sb->sb_checksum = 0;
  
  if (lseek(fd, 0, SEEK_SET) < 0)
    err(1, "lseek(fd, 0, SEEK_SET)");
  done = 0;
  remaining = sb_size;
  while (remaining > 0) {
    w = write(fd, (char *) buffer + done, remaining);
    if (w < 0)
      err(1, "write super block");
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
