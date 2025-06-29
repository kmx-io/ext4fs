/* kc3
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

int ext4fs_block_bitmap (const struct ext4fs_super_block *sb,
                         const struct ext4fs_group_desc *gd,
                         uint64_t *dest)
{
  if (! gd) {
    warnx("ext4fs_block_bitmap: NULL group descriptor");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_block_bitmap: NULL dest");
    return -1;
  }
  *dest = le32toh(gd->gd_block_bitmap_lo);
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_64BIT)
    *dest |= ((uint64_t) le32toh(gd->gd_block_bitmap_hi) << 32);
  return 0;
}

int ext4fs_block_size (const struct ext4fs_super_block *sb,
                       uint32_t *dest)
{
  if (! sb) {
    warnx("ext4fs_block_size: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_block_size: NULL dest");
    return -1;
  }
  *dest = 1 << (sb->sb_log_block_size + 10);
  return 0;
}

int ext4fs_blocks_count (const struct ext4fs_super_block *sb,
                         uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_blocks_count: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_blocks_count: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_blocks_count_lo);
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_64BIT)
    *dest |= ((uint64_t) le32toh(sb->sb_blocks_count_hi) << 32);
  return 0;
}

struct ext4fs_group_desc *
ext4fs_group_desc_read (struct ext4fs_group_desc *gd,
                        int fd,
                        const struct ext4fs_super_block *sb)
{
  uint32_t block_size;
  ssize_t done;
  uint32_t offset;
  ssize_t r;
  ssize_t remaining;
  if (ext4fs_block_size(sb, &block_size))
    return NULL;
  offset = (EXT4FS_SUPER_BLOCK_OFFSET + EXT4FS_SUPER_BLOCK_SIZE +
            (block_size - 1)) / block_size * block_size;
  if (lseek(fd, offset, SEEK_SET) < 0) {
    warn("lseek %u", offset);
    return NULL;
  }
  done = 0;
  remaining = sizeof(struct ext4fs_group_desc);
  while (remaining > 0) {
    r = read(fd, (char *) gd + done, remaining);
    if (r < 0) {
      warn("read super block %ld", remaining);
      return NULL;
    }
    done += r;
    remaining -= r;
  }
  return gd;
}

int ext4fs_inode_bitmap (const struct ext4fs_super_block *sb,
                         const struct ext4fs_group_desc *gd,
                         uint64_t *dest)
{
  if (! gd) {
    warnx("ext4fs_inode_bitmap: NULL group descriptor");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_inode_bitmap: NULL dest");
    return -1;
  }
  *dest = le32toh(gd->gd_inode_bitmap_lo);
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_64BIT)
    *dest |= ((uint64_t) le32toh(gd->gd_inode_bitmap_hi) << 32);
  return 0;
}

int ext4fs_inode_table (const struct ext4fs_super_block *sb,
                        const struct ext4fs_group_desc *gd,
                        uint64_t *dest)
{
  if (! gd) {
    warnx("ext4fs_inode_table: NULL group descriptor");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_inode_table: NULL dest");
    return -1;
  }
  *dest = le32toh(gd->gd_inode_table_lo);
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_64BIT)
    *dest |= ((uint64_t) le32toh(gd->gd_inode_table_hi) << 32);
  return 0;
}

int ext4fs_inspect (int fd)
{
  struct ext4fs_group_desc gd = {0};
  struct ext4fs_super_block sb = {0};
  uint64_t size = 0;
  if (ext4fs_size(fd, &size) ||
      ! size)
    return -1;
  printf("ext4fs_size: %lu\n", size);
  if (! ext4fs_super_block_read(&sb, fd))
    return -1;
  if (ext4fs_inspect_super_block(&sb))
    return -1;
  if (! ext4fs_group_desc_read(&gd, fd, &sb))
    return -1;
  if (ext4fs_inspect_group_desc(&sb, &gd))
    return -1;
  printf("EOF\n");
  return 0;
}
    
int ext4fs_inspect_group_desc (const struct ext4fs_super_block *sb,
                               const struct ext4fs_group_desc *gd)
{
  uint64_t block_bitmap;
  uint64_t inode_bitmap;
  uint64_t inode_table;
  if (ext4fs_block_bitmap(sb, gd, &block_bitmap) ||
      ext4fs_inode_bitmap(sb, gd, &inode_bitmap) ||
      ext4fs_inode_table(sb, gd, &inode_table))
    return -1;
  printf("%%Ext4fs.GroupDesc{gd_block_bitmap: %lu,\n"
         "                   gd_inode_bitmap: %lu,\n"
         "                   gd_inode_table: %lu}\n",
         block_bitmap,
         inode_bitmap,
         inode_table);
  return 0;
}

int ext4fs_inspect_super_block (const struct ext4fs_super_block *sb)
{
  uint64_t blocks_count;
  s_enum *e;
  int first;
  if (ext4fs_blocks_count(sb, &blocks_count))
    return -1;
  printf("%%Ext4fs.SuperBlock{sb_inodes_count: %u,\n"
         "                   sb_blocks_count: %lu,\n"
         "                   sb_rev_level: %u,\n"
         "                   sb_rev_level_minor: %u,\n"
         "                   sb_feature_compat: ",
         le32toh(sb->sb_inodes_count),
         blocks_count,
         le32toh(sb->sb_rev_level),
         le32toh(sb->sb_rev_level_minor));
  e = ext4fs_feature_compat;
  first = 1;
  while (e->name) {
    if (sb->sb_feature_compat & e->value) {
      if (! first)
        printf("|");
      else
        first = 0;
      printf("%s", e->name);
    }
    e++;
  }
  printf(",\n"
         "                   sb_feature_incompat: ");
  e = ext4fs_feature_incompat;
  first = 1;
  while (e->name) {
    if (sb->sb_feature_incompat & e->value) {
      if (! first)
        printf("|");
      else
        first = 0;
      printf("%s", e->name);
    }
    e++;
  }
  printf(",\n"
         "                   sb_feature_ro_compat: ");
  e = ext4fs_feature_ro_compat;
  first = 1;
  while (e->name) {
    if (sb->sb_feature_ro_compat & e->value) {
      if (! first)
        printf("|");
      else
        first = 0;
      printf("%s", e->name);
    }
    e++;
  }
  printf("}\n");
  return 0;
}

int ext4fs_size (int fd, uint64_t *dest)
{
  if (ioctl(fd, BLKGETSIZE64, dest) < 0) {
    warn("ioctl BLKGETSIZE64");
    return -1;
  }
  return 0;
}

struct ext4fs_super_block *
ext4fs_super_block_read (struct ext4fs_super_block *sb,
                         int fd)
{
  ssize_t done;
  ssize_t r;
  ssize_t remaining;
  if (lseek(fd, EXT4FS_SUPER_BLOCK_OFFSET, SEEK_SET) < 0) {
    warn("ext4fs_super_block_read: lseek 1024");
    return NULL;
  }
  done = 0;
  remaining = sizeof(struct ext4fs_super_block);
  while (remaining > 0) {
    r = read(fd, (char *) sb + done, remaining);
    if (r < 0) {
      warn("ext4fs_super_block_read: read super block %ld", remaining);
      return NULL;
    }
    done += r;
    remaining -= r;
  }
  return sb;
}
