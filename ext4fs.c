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
#include "configure.h"
#define _DEFAULT_SOURCE 1

#if defined(OpenBSD)
# include <sys/param.h>
# include <sys/disklabel.h>
# include <sys/dkio.h>
#else
# if defined(Linux)
#  include <linux/fs.h>
# endif
#endif

#include <assert.h>
#include <endian.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ext4fs.h>
#include <crc32c.h>
#include <uuid.h>

const s_value_name ext4fs_bgd_flag_names[] = {
  {EXT4FS_BGD_FLAG_INODE_UNINIT, "inode-uninit"},
  {EXT4FS_BGD_FLAG_BLOCK_UNINIT, "block-uninit"},
  {EXT4FS_BGD_FLAG_INODE_ZEROED, "inode-zeroed"},
  {EXT4FS_BGD_FLAG_DIRTY,        "dirty"},
  {EXT4FS_BGD_FLAG_BLOCK_ZEROED, "block-zeroed"},
  {EXT4FS_BGD_FLAG_READ_ONLY,    "read-only"},
  {0, NULL}
};

const s_value_name ext4fs_checksum_type_names[] = {
  {EXT4FS_CHECKSUM_TYPE_CRC32C, "crc32c"},
  {0, NULL}
};

const s_value_name ext4fs_encoding_names[] = {
  {EXT4FS_ENCODING_UTF8, "utf8"},
  {0, NULL}
};

const s_value_name ext4fs_encoding_flag_names[] = {
  {EXT4FS_ENCODING_FLAG_STRICT_MODE, "utf8"},
  {0, NULL}
};

const char *ext4fs_errors_names[] = {
  "0",
  "continue",
  "remount-ro",
  "panic",
  NULL
};

const s_value_name ext4fs_feature_compat_names[] = {
  {EXT4FS_FEATURE_COMPAT_DIR_PREALLOC,  "dir_prealloc"},
  {EXT4FS_FEATURE_COMPAT_IMAGIC_INODES, "imagic_inodes"},
  {EXT4FS_FEATURE_COMPAT_HAS_JOURNAL,   "has_journal"},
  {EXT4FS_FEATURE_COMPAT_EXT_ATTR,      "ext_attr"},
  {EXT4FS_FEATURE_COMPAT_RESIZE_INODE,  "resize_inode"},
  {EXT4FS_FEATURE_COMPAT_DIR_INDEX,     "dir_index"},
  {0, NULL}
};

const s_value_name ext4fs_feature_incompat_names[] = {
  {EXT4FS_FEATURE_INCOMPAT_COMPRESSION, "compression"},
  {EXT4FS_FEATURE_INCOMPAT_FILETYPE,    "filetype"},
  {EXT4FS_FEATURE_INCOMPAT_RECOVER,     "recover"},
  {EXT4FS_FEATURE_INCOMPAT_JOURNAL_DEV, "journal_dev"},
  {EXT4FS_FEATURE_INCOMPAT_META_BG,     "meta_bg"},
  {EXT4FS_FEATURE_INCOMPAT_EXTENTS,     "extents"},
  {EXT4FS_FEATURE_INCOMPAT_64BIT,       "64bit"},
  {EXT4FS_FEATURE_INCOMPAT_MMP,         "mmp"},
  {EXT4FS_FEATURE_INCOMPAT_FLEX_BG,     "flex_bg"},
  {EXT4FS_FEATURE_INCOMPAT_EA_INODE,    "ea_inode"},
  {EXT4FS_FEATURE_INCOMPAT_DIRDATA,     "dirdata"},
  {EXT4FS_FEATURE_INCOMPAT_CSUM_SEED,   "csum_seed"},
  {EXT4FS_FEATURE_INCOMPAT_LARGEDIR,    "largedir"},
  {EXT4FS_FEATURE_INCOMPAT_INLINE_DATA, "inline_data"},
  {EXT4FS_FEATURE_INCOMPAT_ENCRYPT,     "encrypt"},
  {0, NULL}
};

const s_value_name ext4fs_feature_ro_compat_names[] = {
  {EXT4FS_FEATURE_RO_COMPAT_SPARSE_SUPER,  "sparse_super"},
  {EXT4FS_FEATURE_RO_COMPAT_LARGE_FILE,    "large_file"},
  {EXT4FS_FEATURE_RO_COMPAT_BTREE_DIR,     "btree_dir"},
  {EXT4FS_FEATURE_RO_COMPAT_HUGE_FILE,     "huge_file"},
  {EXT4FS_FEATURE_RO_COMPAT_GDT_CSUM,      "gdt_csum"},
  {EXT4FS_FEATURE_RO_COMPAT_DIR_NLINK,     "dir_nlink"},
  {EXT4FS_FEATURE_RO_COMPAT_EXTRA_ISIZE,   "extra_isize"},
  {EXT4FS_FEATURE_RO_COMPAT_HAS_SNAPSHOT,  "has_snapshot"},
  {EXT4FS_FEATURE_RO_COMPAT_QUOTA,         "quota"},
  {EXT4FS_FEATURE_RO_COMPAT_BIGALLOC,      "bigalloc"},
  {EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM, "metadata_csum"},
  {EXT4FS_FEATURE_RO_COMPAT_REPLICA,       "replica"},
  {EXT4FS_FEATURE_RO_COMPAT_READONLY,      "readonly"},
  {EXT4FS_FEATURE_RO_COMPAT_PROJECT,       "project"},
  {0, NULL}
};

const s_value_name ext4fs_flag_names[] = {
  {EXT4FS_FLAG_SIGNED_HASH, "signed_hash"},
  {EXT4FS_FLAG_UNSIGNED_HASH, "unsigned_hash"},
  {EXT4FS_FLAG_TEST_FILESYS, "test_fs"},
  {EXT4FS_FLAG_64BIT, "64bit"},
  {EXT4FS_FLAG_MOUNT_OPT_CHECK, "mount_opt_check"},
  {0, NULL}
};

const s_value_name ext4fs_inode_flag_names[] = {
  {EXTFS_INODE_FLAG_SECURE_RM                , "secure_rm"},
  {EXTFS_INODE_FLAG_UN_RM                    , "un_rm"},
  {EXTFS_INODE_FLAG_COMPRESSION              , "comp"},
  {EXTFS_INODE_FLAG_SYNC                     , "sync"},
  {EXTFS_INODE_FLAG_IMMUTABLE                , "immutable"},
  {EXTFS_INODE_FLAG_APPEND                   , "append"},
  {EXTFS_INODE_FLAG_NO_DUMP                  , "no_dump"},
  {EXTFS_INODE_FLAG_NO_ATIME                 , "no_atime"},
  {EXTFS_INODE_FLAG_DIRTY                    , "dirty"},
  {EXTFS_INODE_FLAG_COMPRESSED_BLOCKS        , "comp-blk"},
  {EXTFS_INODE_FLAG_NO_COMPRESSION           , "no-comp"},
  {EXTFS_INODE_FLAG_ENCRYPTED                , "encrypted"},
  {EXTFS_INODE_FLAG_INDEX                    , "index"},
  {EXTFS_INODE_FLAG_IMAGIC                   , "imagic"},
  {EXTFS_INODE_FLAG_JOURNAL_DATA             , "journal_data"},
  {EXTFS_INODE_FLAG_NO_TAIL                  , "no_tail"},
  {EXTFS_INODE_FLAG_DIR_SYNC                 , "dir_sync"},
  {EXTFS_INODE_FLAG_TOP_DIR                  , "top_dir"},
  {EXTFS_INODE_FLAG_HUGE_FILE                , "huge_file"},
  {EXTFS_INODE_FLAG_EXTENTS                  , "extents"},
  {EXTFS_INODE_FLAG_EXTENDED_ATTRIBUTES_INODE, "xattrs_inode"},
  {EXTFS_INODE_FLAG_EOF_BLOCKS               , "eof_blocks"},
  {EXTFS_INODE_FLAG_INLINE_DATA              , "inline_data"},
  {EXTFS_INODE_FLAG_PROJECT_ID_INHERITANCE   , "project_id_inheritance"},
  {EXTFS_INODE_FLAG_CASEFOLD                 , "casefold"}
};

const s_value_name ext4fs_mount_names[] = {
  {EXT4FS_MOUNT_READONLY,             "ro"},
  {EXT4FS_MOUNT_NO_ATIME,             "noatime"},
  {EXT4FS_MOUNT_DIRSYNC,              "dirsync"},
  {EXT4FS_MOUNT_DATA_JOURNAL,         "data=journal"},
  {EXT4FS_MOUNT_DATA_ORDERED,         "data=ordered"},
  {EXT4FS_MOUNT_DATA_WRITEBACK,       "data=writeback"},
  {EXT4FS_MOUNT_ERRORS_CONTINUE,      "errors=continue"},
  {EXT4FS_MOUNT_ERRORS_REMOUNT_RO,    "errors=remount-ro"},
  {EXT4FS_MOUNT_ERRORS_PANIC,         "errors=panic"},
  {EXT4FS_MOUNT_DISCARD,              "discard"},
  {EXT4FS_MOUNT_NO_BUFFER_HEADS,      "no-buffer-heads"},
  {EXT4FS_MOUNT_SKIP_JOURNAL,         "skip-journal"},
  {EXT4FS_MOUNT_NOAUTO_DELAYED_ALLOC, "noauto-delayed-alloc"},
  {0, NULL}
};

const char *ext4fs_os_names[] = {
  "Linux",
  "Hurd",
  "Masix",
  "FreeBSD",
  "Lites",
  "OpenBSD",
  NULL
};

const s_value_name ext4fs_state_names[] = {
  {EXT4FS_STATE_VALID, "valid"},
  {EXT4FS_STATE_ERROR, "error"},
  {0, NULL}
};

int ext4fs_64bit (const struct ext4fs_super_block *sb)
{
  return (le32toh(sb->sb_feature_incompat) &
          EXT4FS_FEATURE_INCOMPAT_64BIT) ? 1 : 0;
}

int
ext4fs_bgd_block_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le32toh(bgd->bgd_block_bitmap_block_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(bgd->bgd_block_bitmap_block_hi) << 32;
  return 0;
}

int
ext4fs_bgd_block_bitmap_checksum
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_block_bitmap_checksum_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_block_bitmap_checksum_hi) << 16;
  return 0;
}

int
ext4fs_bgd_checksum_compute
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t block_group_id, uint16_t *dest)
{
  uint32_t block_group_id_le;
  uint32_t crc;
  uint32_t seed;
  size_t size;
  struct ext4fs_block_group_descriptor tmp = {0};
  assert(sb);
  assert(bgd);
  assert(dest);
  if (! (sb->sb_feature_ro_compat & EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM)) {
    *dest = 0;
    return 0;
  }
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_CSUM_SEED)
    seed = le32toh(sb->sb_checksum_seed);
  else {
    block_group_id_le = htole32(block_group_id);
    seed = crc32c(0, sb->sb_uuid, sizeof(sb->sb_uuid));
    seed = crc32c(seed, &block_group_id_le, sizeof(block_group_id_le));
  }
  if (ext4fs_64bit(sb))
    size = le16toh(sb->sb_block_group_descriptor_size);
  else
    size = 32;
  if (size > sizeof(tmp))
    return -1;
  memcpy(&tmp, bgd, size);
  tmp.bgd_checksum = 0;
  crc = crc32c(seed, &tmp, size);
  *dest = (~crc) & 0xFFFF;
  return 0;
}

int
ext4fs_bgd_exclude_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le32toh(bgd->bgd_exclude_bitmap_block_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(bgd->bgd_exclude_bitmap_block_hi) << 32;
  return 0;
}

int
ext4fs_bgd_free_blocks_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_free_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_free_blocks_count_hi) << 16;
  return 0;
}

int
ext4fs_bgd_free_inodes_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_free_inodes_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_free_inodes_count_hi) << 16;
  return 0;
}

int
ext4fs_bgd_inode_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le32toh(bgd->bgd_inode_bitmap_block_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(bgd->bgd_inode_bitmap_block_hi) << 32;
  return 0;
}

int
ext4fs_bgd_inode_bitmap_checksum
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_inode_bitmap_checksum_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_inode_bitmap_checksum_hi) << 16;
  return 0;
}

int
ext4fs_bgd_inode_table_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le32toh(bgd->bgd_inode_table_block_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(bgd->bgd_inode_table_block_hi) << 32;
  return 0;
}

int
ext4fs_bgd_inode_table_unused
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_inode_table_unused_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_inode_table_unused_hi) << 16;
  return 0;
}

int
ext4fs_bgd_used_dirs_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest)
{
  assert(sb);
  assert(bgd);
  assert(dest);
  *dest = le16toh(bgd->bgd_used_dirs_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(bgd->bgd_used_dirs_count_hi) << 16;
  return 0;
}

struct ext4fs_block_group_descriptor *
ext4fs_block_group_descriptor_read
(const struct ext4fs_super_block *sb,
 struct ext4fs_block_group_descriptor *bgd,
 uint64_t bgd_count,
 int fd)
{
  uint32_t block_size;
  ssize_t done;
  uint32_t offset;
  ssize_t r;
  ssize_t remaining;
  assert(sb);
  assert(bgd);
  if (ext4fs_sb_block_size(sb, &block_size))
    return NULL;
  offset = (EXT4FS_SUPER_BLOCK_OFFSET + EXT4FS_SUPER_BLOCK_SIZE +
            (block_size - 1)) / block_size * block_size;
  if (lseek(fd, offset, SEEK_SET) < 0) {
    warn("lseek %u", offset);
    return NULL;
  }
  done = 0;
  remaining = sizeof(struct ext4fs_block_group_descriptor) *
    bgd_count;
  while (remaining > 0) {
    r = read(fd, (char *) bgd + done, remaining);
    if (r < 0) {
      warn("read super block %ld", remaining);
      return NULL;
    }
    done += r;
    remaining -= r;
  }
  return bgd;
}

#ifdef OpenBSD

struct disklabel *
ext4fs_disklabel_get (struct disklabel *dl, int fd)
{
  assert(dl);
  if (ioctl(fd, DIOCGDINFO, (char *) dl) == -1) {
    warn("disklabel_get: ioctl DIOCGDINFO");
    return NULL;
  }
  return dl;
}

#endif /* OpenBSD */

int
ext4fs_inode_256_checksum_compute
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode_256 *inode_256,
 uint32_t inode_number,
 uint32_t *dest)
{
  uint32_t crc;
  uint32_t inode_number_le;
  uint32_t seed;
  struct ext4fs_inode_256 tmp = {0};
  assert(sb);
  assert(inode_256);
  assert(dest);
  if (! (sb->sb_feature_ro_compat & EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM)) {
    *dest = 0;
    return 0;
  }
  if (sb->sb_feature_incompat & EXT4FS_FEATURE_INCOMPAT_CSUM_SEED)
    seed = le32toh(sb->sb_checksum_seed);
  else {
    seed = crc32c(0, sb->sb_uuid, sizeof(sb->sb_uuid));
  }
  inode_number_le = htole32(inode_number);
  crc = crc32c(seed, &inode_number_le, sizeof(inode_number_le));
  crc = crc32c(crc, &inode_256->inode.i_nfs_generation,
               sizeof(inode_256->inode.i_nfs_generation));
  tmp = *inode_256;
  tmp.inode.i_checksum_lo = 0;
  tmp.inode.i_checksum_hi = 0;
  crc = crc32c(crc, &tmp, sizeof(tmp));
  *dest = ~crc;
  return 0;
}

struct ext4fs_inode_256 *
ext4fs_inode_256_read
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd_table,
 struct ext4fs_inode_256 *inode_256, 
 uint32_t inode_number,
 int fd)
{
  uint32_t block_group;
  uint32_t block_size;
  uint32_t inode_index;
  uint64_t inode_offset;
  uint16_t inode_size;
  uint64_t inode_table_block;
  ssize_t done;
  ssize_t r;
  ssize_t remaining;
  assert(sb);
  assert(bgd_table);
  assert(inode_256);
  if (inode_number < 1) {
    fprintf(stderr, "ext4fs_inode_256_read: invalid inode number %u\n",
            inode_number);
    return NULL;
  }
  block_group = (inode_number - 1) / le32toh(sb->sb_inodes_per_group);
  inode_index = (inode_number - 1) % le32toh(sb->sb_inodes_per_group);
  if (block_group >= ext4fs_sb_block_group_count(sb)) {
    fprintf(stderr, "ext4fs_inode_256_read: block group %u out of range\n",
            block_group);
    return NULL;
  }
  if (ext4fs_sb_block_size(sb, &block_size)) {
    fprintf(stderr, "ext4fs_inode_256_read: ext4fs_sb_block_size\n");
    return NULL;
  }
  if (ext4fs_bgd_inode_table_block(sb, &bgd_table[block_group],
                                   &inode_table_block)) {
    fprintf(stderr,
            "ext4fs_inode_256_read: ext4fs_bgd_inode_table_block\n");
    return NULL;
  }
  if (ext4fs_sb_inode_size(sb, &inode_size))
    return NULL;
  inode_offset = inode_table_block * block_size +
    inode_index * inode_size;
  if (lseek(fd, inode_offset, SEEK_SET) < 0) {
    warn("ext4fs_inode_256_read: lseek %lu", inode_offset);
    return NULL;
  }
  if (sizeof(struct ext4fs_inode_256) != inode_size) {
    fprintf(stderr, "ext4fs_inode_256_read: invalid inode size: %u",
            inode_size);
    return NULL;
  }
  done = 0;
  remaining = inode_size;
  while (remaining > 0) {
    r = read(fd, (char *) inode_256 + done, remaining);
    if (r < 0) {
      warn("ext4fs_inode_256_read: read inode %ld", remaining);
      return NULL;
    }
    done += r;
    remaining -= r;
  }
  return inode_256;
}

int
ext4fs_inode_blocks
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest)
{
  assert(sb);
  assert(inode);
  assert(dest);
  *dest = le32toh(inode->i_blocks_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le16toh(inode->i_blocks_hi) << 32;
  return 0;
}

int
ext4fs_inode_checksum
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint32_t *dest)
{
  assert(sb);
  assert(inode);
  assert(dest);
  *dest = le16toh(inode->i_checksum_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(inode->i_checksum_hi) << 16;
  return 0;
}

int
ext4fs_inode_extended_attributes
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest)
{
  assert(inode);
  assert(dest);
  *dest = le32toh(inode->i_extended_attributes_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le16toh(inode->i_extended_attributes_hi) << 32;
  return 0;
}

int
ext4fs_inode_gid
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint32_t *dest)
{
  assert(sb);
  assert(inode);
  assert(dest);
  *dest = le16toh(inode->i_gid_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(inode->i_gid_hi) << 16;
  return 0;
}

int
ext4fs_inode_size
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest)
{
  assert(sb);
  assert(inode);
  assert(dest);
  *dest = le32toh(inode->i_size_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(inode->i_size_hi) << 32;
  return 0;
}

int
ext4fs_inode_uid
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint32_t *dest)
{
  assert(sb);
  assert(inode);
  assert(dest);
  *dest = le16toh(inode->i_uid_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint32_t) le16toh(inode->i_uid_hi) << 16;
  return 0;
}

int ext4fs_inspect (const char *dev, int fd)
{
  struct ext4fs_block_group_descriptor *bgd = NULL;
  uint64_t                              bgd_count = 0;
  uint64_t i;
  uint32_t inode_number = 0;
  struct ext4fs_inode_256 inode_256 = {0};
  struct ext4fs_super_block sb = {0};
  uint16_t                  sb_inode_size;
  uint64_t size = 0;
  assert(dev);
  if (ext4fs_size(dev, fd, &size) ||
      ! size)
    return -1;
  printf("ext4fs_size: " CONFIGURE_FMT_UINT64 "\n", size);
  if (! ext4fs_super_block_read(&sb, fd))
    return -1;
  if (ext4fs_inspect_super_block(&sb))
    return -1;
  if (! (bgd_count = ext4fs_sb_block_group_count(&sb)))
    return -1;
  printf("ext4fs_block_group_count: " CONFIGURE_FMT_UINT64 "\n",
         bgd_count);
  bgd = calloc(bgd_count, sizeof(struct ext4fs_block_group_descriptor));
  if (! bgd)
    return -1;
  if (! ext4fs_block_group_descriptor_read(&sb, bgd, bgd_count, fd))
    return -1;
  i = 0;
  while (i < bgd_count) {
    printf("# " CONFIGURE_FMT_UINT64 "\n", i);
    if (ext4fs_inspect_block_group_descriptor(&sb, bgd + i, i)) {
      fprintf(stderr, "ext4fs_inspect:"
              " ext4fs_inspect_block_group_descriptor\n");
      return -1;
    }
    i++;
  }
  inode_number = 2;
  if (ext4fs_sb_inode_size(&sb, &sb_inode_size))
    return -1;
  if (sb_inode_size == 256) {
    if (! ext4fs_inode_256_read(&sb, bgd, &inode_256, inode_number, fd)) {
      fprintf(stderr, "ext4fs_inspect: ext4fs_inode_256_read\n");
      return -1;
    }
    printf("# %u\n", inode_number);
    if (ext4fs_inspect_inode_256(&sb, &inode_256, inode_number)) {
      fprintf(stderr, "ext4fs_inspect: ext4fs_inspect_inode_256\n");
      return -1;
    }
  }
  printf("\n"
         "EOF\n");
  return 0;
}

int ext4fs_inspect_inode_256 (const struct ext4fs_super_block *sb,
                              const struct ext4fs_inode_256 *inode_256,
                              uint32_t inode_number)
{
  uint32_t atime;
  char     atime_str[32] = {0};
  uint64_t blocks;
  uint32_t checksum;
  uint32_t checksum_computed;
  uint32_t ctime;
  char     ctime_str[32] = {0};
  struct ext4fs_extent_header eh = {0};
  uint64_t extended_attributes;
  struct ext4fs_extent extent = {0};
  int      i;
  char     mode_str[14] = {0};
  uint32_t mtime;
  char     mtime_str[32] = {0};
  uint32_t dtime;
  char     dtime_str[32] = {0};
  uint32_t gid;
  uint16_t mode;
  uint64_t size;
  uint32_t uid;
  assert(sb);
  assert(inode_256);
  mode = le16toh(inode_256->inode.i_mode);
  atime = le32toh(inode_256->inode.i_atime);
  ctime = le32toh(inode_256->inode.i_ctime);
  mtime = le32toh(inode_256->inode.i_mtime);
  dtime = le32toh(inode_256->inode.i_dtime);
  if (ext4fs_mode_to_str(mode, mode_str, sizeof(mode_str)) ||
      ext4fs_inode_uid(sb, &inode_256->inode, &uid) ||
      ext4fs_inode_size(sb, &inode_256->inode, &size) ||
      ext4fs_time_to_str(atime, atime_str, sizeof(atime_str)) ||
      ext4fs_time_to_str(ctime, ctime_str, sizeof(ctime_str)) ||
      ext4fs_time_to_str(mtime, mtime_str, sizeof(mtime_str)) ||
      ext4fs_time_to_str(dtime, dtime_str, sizeof(dtime_str)) ||
      ext4fs_inode_gid(sb, &inode_256->inode, &gid) ||
      ext4fs_inode_blocks(sb, &inode_256->inode, &blocks) ||
      ext4fs_inode_extended_attributes(sb, &inode_256->inode,
                                       &extended_attributes) ||
      ext4fs_inode_checksum(sb, &inode_256->inode, &checksum) ||
      ext4fs_inode_256_checksum_compute(sb, inode_256, inode_number,
                                        &checksum_computed))
    return -1;
  printf("%%Ext4fs.Inode256{i_mode: (U16) %u,\t# %s\n"
         "                 i_uid: (U32) %u,\n"
         "                 i_size: (U64) " CONFIGURE_FMT_UINT64 ",\n"
         "                 i_atime: %%Time{tv_sec: %u,\t# %s\n"
         "                                tv_nsec: %u},\n"
         "                 i_ctime: %%Time{tv_sec: %u,\t# %s\n"
         "                                tv_nsec: %u},\n"
         "                 i_mtime: %%Time{tv_sec: %u,\t# %s\n"
         "                                tv_nsec: %u},\n"
         "                 i_dtime: (U32) %u,\t# %s\n"
         "                 i_gid: (U32) %u,\n"
         "                 i_links_count: (U16) %u,\n"
         "                 i_blocks: (U64) " CONFIGURE_FMT_UINT64 ",\n"
         "                 i_flags: ",
         mode, mode_str,
         uid,
         size,
         atime, atime_str, le32toh(inode_256->inode.i_atime_extra),
         ctime, ctime_str, le32toh(inode_256->inode.i_ctime_extra),
         mtime, mtime_str, le32toh(inode_256->inode.i_mtime_extra),
         dtime, dtime_str,
         gid,
         le16toh(inode_256->inode.i_links_count),
         blocks);
  if (ext4fs_inspect_flag_names(le32toh(inode_256->inode.i_flags),
                                ext4fs_inode_flag_names))
    return -1;
  printf(",\n"
         "                 i_version: (U32) %u,\n",
         le32toh(inode_256->inode.i_version));
  printf("                 i_extent_header:\n");
  eh = inode_256->inode.i_extent_header;
  ext4fs_inspect_extent_header(&eh, 2);
  printf(",\n");
  if (! eh.eh_depth) {
    printf("                 i_extent: {\t# eh_depth == 0\n");
    i = 0;
    while (i < eh.eh_entries) {
      printf("  # %i\n",
             i);
      extent = inode_256->inode.i_extent[i];
      if (ext4fs_inspect_extent(&extent, 2))
        return -1;
      printf(",\n");
      i++;
    }
  }
  printf("                 },\n"
         "                 i_nfs_generation: (U32) %u,\n"
         "                 i_extended_attributes: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                 i_fragment_address: (U32) %u,\n"
         "                 i_checksum: (U32) 0x%08X} # 0x%08X",
         le32toh(inode_256->inode.i_nfs_generation),
         extended_attributes,
         le32toh(inode_256->inode.i_fragment_address),
         checksum, checksum_computed);
  return 0;
}

int ext4fs_extent_start (const struct ext4fs_extent *extent,
                         uint64_t *start)
{
  assert(extent);
  assert(start);
  *start = le32toh(extent->e_start_lo);
  *start |= (uint64_t) le16toh(extent->e_start_hi) << 32;
  return 0;
}

int ext4fs_inspect_extent (const struct ext4fs_extent *extent,
                           uint8_t indent)
{
  char s[80] = {0};
  uint64_t start;
  assert(extent);
  if (indent >= sizeof(s))
    return -1;
  memset(s, ' ', indent);
  if (ext4fs_extent_start(extent, &start))
    return -1;
  printf("%s%%Ext4fs.Extent{e_block: (U32) %u,\n"
         "%s               e_len: (U16) %u,\n"
         "%s               e_start: (U64) " CONFIGURE_FMT_UINT64 "}",
         s, le32toh(extent->e_block),
         s, le16toh(extent->e_len),
         s, start);
  return 0;
}

int ext4fs_inspect_extent_header (const struct ext4fs_extent_header *eh,
                                  uint8_t indent)
{
  char s[80] = {0};
  assert(eh);
  if (indent >= sizeof(s))
    return -1;
  memset(s, ' ', indent);
  printf("%s%%Ext4fs.ExtentHeader{eh_magic: (U16) 0x%04X,\t# 0xF30A\n"
         "%s                     eh_entries: (U16) %u,\n"
         "%s                     eh_max: (U16) %u,\n"
         "%s                     eh_depth: (U16) %u,\n"
         "%s                     eh_generation: (U32) %u}",
         s, le16toh(eh->eh_magic),
         s, le16toh(eh->eh_entries),
         s, le16toh(eh->eh_max),
         s, le16toh(eh->eh_depth),
         s, le32toh(eh->eh_generation));
  return 0;
}

int ext4fs_mode_to_str (uint16_t mode, char *dest, size_t size)
{
  assert(dest);
  if (size < 14)
    return -1;
  memset(dest, 0, 14);
  if (S_ISREG(mode))
    dest[0] = '-';
  else if (S_ISDIR(mode))
    dest[0] = 'd';
  else if (S_ISLNK(mode))
    dest[0] = 'l';
  else if (S_ISCHR(mode))
    dest[0] = 'c';
  else if (S_ISBLK(mode))
    dest[0] = 'b';
  else if (S_ISFIFO(mode))
    dest[0] = 'f';
  else if (S_ISSOCK(mode))
    dest[0] = 's';
  dest[1]  = (S_ISUID & mode) ? 'U' : '-';
  dest[2]  = (S_ISGID & mode) ? 'G' : '-';
  dest[3]  = (S_ISVTX & mode) ? 'v' : '-';
  dest[4]  = (S_IRUSR & mode) ? 'r' : '-';
  dest[5]  = (S_IWUSR & mode) ? 'w' : '-';
  dest[6]  = (S_IXUSR & mode) ? 'x' : '-';
  dest[7]  = (S_IRGRP & mode) ? 'r' : '-';
  dest[8]  = (S_IWGRP & mode) ? 'w' : '-';
  dest[9]  = (S_IXGRP & mode) ? 'x' : '-';
  dest[10] = (S_IROTH & mode) ? 'r' : '-';
  dest[11] = (S_IWOTH & mode) ? 'w' : '-';
  dest[12] = (S_IXOTH & mode) ? 'x' : '-';
  return 0;
}

void ext4fs_inspect_os (uint32_t os)
{
  if (os < sizeof(ext4fs_os_names) / sizeof(const char *) - 1)
    printf("%s", ext4fs_os_names[os]);
  else
    printf("(U32) %u", os);
}

int ext4fs_inspect_flag_names (uint32_t flags,
                               const s_value_name *names)
{
  char first;
  const s_value_name *i;
  uint32_t remaining;
  assert(names);
  first = 1;
  i = names;
  remaining = flags;
  while (i->name) {
    if (flags & i->value) {
      if (! first)
        printf(" | ");
      else
        first = 0;
      printf("%s", i->name);
      remaining &= ~i->value;
    }
    i++;
  }
  if (first)
    printf("0x%04X", remaining);
  else if (remaining)
    printf(" | 0x%04X", remaining);
  return 0;
}

void ext4fs_inspect_errors (uint16_t errors)
{
  if (errors < sizeof(ext4fs_errors_names) / sizeof(const char *) - 1)
    printf("%s", ext4fs_errors_names[errors]);
  else
    printf("(U16) %u", errors);
}
    
int
ext4fs_inspect_block_group_descriptor
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t block_group_id)
{
  uint64_t block_bitmap_block;
  uint32_t block_bitmap_checksum;
  uint16_t checksum = 0;
  uint16_t checksum_computed;
  uint64_t exclude_bitmap_block;
  uint32_t free_blocks_count;
  uint32_t free_inodes_count;
  uint64_t inode_bitmap_block;
  uint32_t inode_bitmap_checksum;
  uint64_t inode_table_block;
  uint32_t inode_table_unused;
  uint32_t used_dirs_count;
  assert(sb);
  assert(bgd);
  if (ext4fs_bgd_block_bitmap_block(sb, bgd, &block_bitmap_block) ||
      ext4fs_bgd_inode_bitmap_block(sb, bgd, &inode_bitmap_block) ||
      ext4fs_bgd_inode_table_block(sb, bgd, &inode_table_block) ||
      ext4fs_bgd_free_blocks_count(sb, bgd, &free_blocks_count) ||
      ext4fs_bgd_free_inodes_count(sb, bgd, &free_inodes_count) ||
      ext4fs_bgd_used_dirs_count(sb, bgd, &used_dirs_count) ||
      ext4fs_bgd_exclude_bitmap_block(sb, bgd, &exclude_bitmap_block) ||
      ext4fs_bgd_block_bitmap_checksum(sb, bgd,
                                       &block_bitmap_checksum) ||
      ext4fs_bgd_inode_bitmap_checksum(sb, bgd,
                                       &inode_bitmap_checksum) ||
      ext4fs_bgd_inode_table_unused(sb, bgd, &inode_table_unused) ||
      ext4fs_bgd_checksum_compute(sb, bgd, block_group_id,
                                  &checksum_computed))
    return -1;
  checksum = le16toh(bgd->bgd_checksum);
  printf("%%Ext4fs.BlockGroupDescriptor{bgd_block_bitmap_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                             bgd_inode_bitmap_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                             bgd_inode_table_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                             bgd_free_blocks_count: (U32) %u,\n"
         "                             bgd_free_inodes_count: (U32) %u,\n"
         "                             bgd_used_dirs_count: (U32) %u,\n"
         "                             bgd_flags: ",
         block_bitmap_block,
         inode_bitmap_block,
         inode_table_block,
         free_blocks_count,
         free_inodes_count,
         used_dirs_count);
  ext4fs_inspect_flag_names(bgd->bgd_flags, ext4fs_bgd_flag_names);
  printf(",\n"
         "                             bgd_exclude_bitmap_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                             bgd_block_bitmap_checksum: "
         "(U32) 0x%08X,\n"
         "                             bgd_inode_bitmap_checksum: "
         "(U32) 0x%08X,\n"
         "                             bgd_inode_table_unused: "
         "(U32) %u,\n"
         "                             bgd_checksum: (U16) 0x%04X} # 0x%04X\n",
         exclude_bitmap_block,
         block_bitmap_checksum,
         inode_bitmap_checksum,
         inode_table_unused,
         checksum, checksum_computed);
  return 0;
}

int
ext4fs_inspect_block_group_descriptor_hex
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd)
{
  uint16_t i = 0;
  const uint8_t *p;
  uint16_t size;
  assert(sb);
  assert(bgd);
  p = (uint8_t *) bgd;
  size = le16toh(sb->sb_block_group_descriptor_size);
  while (i < size) {
    printf("%02X ", *p);
    if (i % 16 == 15)
      printf("\n");
    i++;
    p++;
  }
  return 0;
}

int ext4fs_inspect_super_block (const struct ext4fs_super_block *sb)
{
  uint64_t blocks_count;
  uint64_t check_time;
  uint32_t checksum;
  uint32_t checksum_computed = 0;
  uint64_t first_error_time;
  char     first_error_function[EXT4FS_FUNCTION_MAX + 1] = {0};
  uint64_t free_blocks_count;
  char     last_error_function[EXT4FS_FUNCTION_MAX + 1] = {0};
  uint64_t last_error_time;
  char     last_mounted[EXT4FS_LAST_MOUNTED_MAX + 1] = {0};
  char     mount_opts[EXT4FS_MOUNT_OPTS_MAX + 1] = {0};
  uint64_t mount_time;
  uint64_t newfs_time;
  uint64_t reserved_blocks_count;
  char str_check_time[32] = {0};
  char str_mount_time[32] = {0};
  char str_write_time[32] = {0};
  char str_newfs_time[32] = {0};
  char str_first_error_time[32] = {0};
  char str_last_error_time[32] = {0};
  char volume_name[EXT4FS_VOLUME_NAME_MAX + 1] = {0};
  uint64_t write_time;
  assert(sb);
  checksum = le32toh(sb->sb_checksum);
  if (ext4fs_sb_blocks_count(sb, &blocks_count) ||
      ext4fs_sb_reserved_blocks_count(sb, &reserved_blocks_count) ||
      ext4fs_sb_free_blocks_count(sb, &free_blocks_count) ||
      ext4fs_sb_mount_time(sb, &mount_time) ||
      ext4fs_sb_write_time(sb, &write_time) ||
      ext4fs_sb_check_time(sb, &check_time) ||
      ext4fs_sb_newfs_time(sb, &newfs_time) ||
      ext4fs_sb_first_error_time(sb, &first_error_time) ||
      ext4fs_sb_last_error_time(sb, &last_error_time) ||
      ext4fs_time_to_str(mount_time, str_mount_time,
                         sizeof(str_mount_time)) ||
      ext4fs_time_to_str(write_time, str_write_time,
                         sizeof(str_write_time)) ||
      ext4fs_time_to_str(check_time, str_check_time,
                         sizeof(str_check_time)) ||
      ext4fs_time_to_str(newfs_time, str_newfs_time,
                         sizeof(str_newfs_time)) ||
      ext4fs_time_to_str(first_error_time, str_first_error_time,
                         sizeof(str_first_error_time)) ||
      ext4fs_time_to_str(last_error_time, str_last_error_time,
                         sizeof(str_last_error_time)) ||
      ext4fs_sb_checksum_compute(sb, &checksum_computed))
    return -1;
  strlcpy(volume_name, sb->sb_volume_name, sizeof(volume_name));
  strlcpy(last_mounted, sb->sb_last_mounted, sizeof(last_mounted));
  strlcpy(first_error_function, sb->sb_first_error_function,
          sizeof(first_error_function));
  strlcpy(last_error_function, sb->sb_last_error_function,
          sizeof(last_error_function));
  strlcpy(mount_opts, sb->sb_mount_opts,
          sizeof(mount_opts));
  printf("%%Ext4fs.SuperBlock{sb_inodes_count: (U32) %u,\n"
         "                   sb_blocks_count: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_reserved_blocks_count: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_free_blocks_count: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_free_inodes_count: (U32) %u,\n"
         "                   sb_first_data_block: (U32) %u,\n"
         "                   sb_log_block_size: (U32) %u,  \t# %u\n"
         "                   sb_log_cluster_size: (U32) %u,\t# %u\n"
         "                   sb_blocks_per_group: (U32) %u,\n"
         "                   sb_clusters_per_group: (U32) %u,\n"
         "                   sb_inodes_per_group: (U32) %u,\n"
         "                   sb_mount_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_write_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_mount_count: (U16) %u,\n"
         "                   sb_max_mount_count: (S16) %d,\n"
         "                   sb_magic: (U16) 0x%04X,\t\t# %u\n"
         "                   sb_state: ",
         le32toh(sb->sb_inodes_count),
         blocks_count, reserved_blocks_count, free_blocks_count,
         le32toh(sb->sb_free_inodes_count),
         le32toh(sb->sb_first_data_block),
         le32toh(sb->sb_log_block_size),
         (uint32_t) 1 << (le32toh(sb->sb_log_block_size) + 10), 
         le32toh(sb->sb_log_cluster_size),
         (uint32_t) 1 << (le32toh(sb->sb_log_cluster_size) + 10), 
         le32toh(sb->sb_blocks_per_group),
         le32toh(sb->sb_clusters_per_group),
         le32toh(sb->sb_inodes_per_group),
         mount_time, str_mount_time,
         write_time, str_write_time,
         le16toh(sb->sb_mount_count),
         (int16_t) le16toh(sb->sb_max_mount_count_before_fsck),
         le16toh(sb->sb_magic), le16toh(sb->sb_magic));
  ext4fs_inspect_flag_names(le16toh(sb->sb_state), ext4fs_state_names);
  printf(",\n"
         "                   sb_errors: ");
  ext4fs_inspect_errors(le16toh(sb->sb_errors));
  printf(",\n"
         "                   sb_revision_level_minor: (U16) %u,\n"
         "                   sb_check_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_check_interval: (U32) %u,\n"
         "                   sb_creator_os: (U32) %u,\t\t# ",
         le32toh(sb->sb_revision_level_minor),
         check_time, str_check_time,
         le32toh(sb->sb_check_interval),
         le32toh(sb->sb_creator_os));
  ext4fs_inspect_os(le32toh(sb->sb_creator_os));
  printf("\n"
         "                   sb_revision_level: (U32) %u,\n"
         "                   sb_default_reserved_uid: (U16) %u,\n"
         "                   sb_default_reserved_gid: (U16) %u,\n"
         "                   sb_feature_compat: ",
         le32toh(sb->sb_revision_level),
         le16toh(sb->sb_default_reserved_uid),
         le16toh(sb->sb_default_reserved_gid));
  ext4fs_inspect_flag_names(le32toh(sb->sb_feature_compat),
                             ext4fs_feature_compat_names);
  printf(",\n"
         "                   sb_feature_incompat: ");
  ext4fs_inspect_flag_names(le32toh(sb->sb_feature_incompat),
                             ext4fs_feature_incompat_names);
  printf(",\n"
         "                   sb_feature_ro_compat: ");
  ext4fs_inspect_flag_names(le32toh(sb->sb_feature_ro_compat),
                             ext4fs_feature_ro_compat_names);
  printf(",\n"
         "                   sb_uuid: ");
  uuid_print(sb->sb_uuid);
  printf(",\n"
         "                   sb_volume_name: %s,\n"
         "                   sb_last_mounted: %s,\n"
         "                   sb_algorithm_usage_bitmap: (U32) %u,\n"
         "                   sb_preallocate_blocks: (U8) %u,\n"
         "                   sb_preallocate_dir_blocks: (U8) %u,\n"
         "                   sb_reserved_bgdt_blocks: (U16) %u,\n"
         "                   sb_journal_uuid: ",
         volume_name,
         last_mounted,
         le32toh(sb->sb_algorithm_usage_bitmap),
         sb->sb_preallocate_blocks,
         sb->sb_preallocate_dir_blocks,
         le16toh(sb->sb_reserved_bgdt_blocks));
  uuid_print(sb->sb_journal_uuid);
  printf(",\n"
         "                   sb_journal_inode_number: (U32) %u,\n"
         "                   sb_journal_device_number: (U32) %u,\n"
         "                   sb_last_orphan: (U32) %u,\n"
         "                   sb_hash_seed: (U32) {0x%08x,\n"
         "                                        0x%08x,\n"
         "                                        0x%08x,\n"
         "                                        0x%08x},\n"
         "                   sb_default_hash_version: %u,\n"
         "                   sb_journal_backup_type: %u,\n"
         "                   sb_block_group_descriptor_size: (U16) %u,\n"
         "                   sb_default_mount_opts: ",
         le32toh(sb->sb_journal_inode_number),
         le32toh(sb->sb_journal_device_number),
         le32toh(sb->sb_last_orphan),
         sb->sb_hash_seed[0], sb->sb_hash_seed[1], sb->sb_hash_seed[2],
         sb->sb_hash_seed[3],
         sb->sb_default_hash_version,
         sb->sb_journal_backup_type,
         le16toh(sb->sb_block_group_descriptor_size));
  ext4fs_inspect_flag_names(le32toh(sb->sb_default_mount_opts),
                             ext4fs_mount_names);
  printf(",\n"
         "                   sb_first_meta_block_group: (U32) %u,\n"
         "                   sb_newfs_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_jnl_blocks: (U32) {0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X, 0x%08X,\n"
         "                                         0x%08X},\n"
         "                   sb_inode_size_extra_min: (U16) %u,\n"
         "                   sb_inode_size_extra_want: (U16) %u,\n"
         "                   sb_flags: ",
         le32toh(sb->sb_first_meta_block_group),
         newfs_time, str_newfs_time,
         le32toh(sb->sb_jnl_blocks[0]), le32toh(sb->sb_jnl_blocks[1]),
         le32toh(sb->sb_jnl_blocks[2]), le32toh(sb->sb_jnl_blocks[3]),
         le32toh(sb->sb_jnl_blocks[4]), le32toh(sb->sb_jnl_blocks[5]),
         le32toh(sb->sb_jnl_blocks[6]), le32toh(sb->sb_jnl_blocks[7]),
         le32toh(sb->sb_jnl_blocks[8]), le32toh(sb->sb_jnl_blocks[9]),
         le32toh(sb->sb_jnl_blocks[10]), le32toh(sb->sb_jnl_blocks[11]),
         le32toh(sb->sb_jnl_blocks[12]), le32toh(sb->sb_jnl_blocks[13]),
         le32toh(sb->sb_jnl_blocks[14]), le32toh(sb->sb_jnl_blocks[15]),
         le32toh(sb->sb_jnl_blocks[16]),
         le16toh(sb->sb_inode_size_extra_min),
         le16toh(sb->sb_inode_size_extra_want));
  ext4fs_inspect_flag_names(le32toh(sb->sb_flags), ext4fs_flag_names);
  printf(",\n"
         "                   sb_raid_stride_block_count: %u,\n"
         "                   sb_mmp_interval: (U32) %u,\n"
         "                   sb_mmp_block: (U32) %u,\n"
         "                   sb_raid_stripe_width_block_count: (U32) %u,\n"
         "                   sb_log_groups_per_flex: %u,\t\t# %u,\n"
         "                   sb_checksum_type: ",
         le16toh(sb->sb_raid_stride_block_count),
         le32toh(sb->sb_mmp_interval),
         le32toh(sb->sb_mmp_block),
         le32toh(sb->sb_raid_stripe_width_block_count),
         sb->sb_log_groups_per_flex, 1 << sb->sb_log_groups_per_flex);
  ext4fs_inspect_flag_names(le16toh(sb->sb_checksum_type),
                            ext4fs_checksum_type_names);
  printf(",\n"
         "                   sb_kilobytes_written: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_error_count: (U32) %u,\n"
         "                   sb_first_error_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_first_error_inode: (U32) %u,\n"
         "                   sb_first_error_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_first_error_function: \"%s\",\n"
         "                   sb_first_error_line: (U32) %u,\n"
         "                   sb_last_error_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_last_error_inode: (U32) %u,\n"
         "                   sb_last_error_line: (U32) %u,\n"
         "                   sb_last_error_block: (U64) "
         CONFIGURE_FMT_UINT64 ",\n"
         "                   sb_last_error_function: \"%s\",\n"
         "                   sb_mount_opts: \"%s\",\n"
         "                   sb_user_quota_inode: (U32) %u,\n"
         "                   sb_group_quota_inode: (U32) %u,\n"
         "                   sb_overhead_clusters: (U32) %u,\n"
         "                   sb_backup_block_groups: (U32) {%u, %u},\n"
         "                   sb_encrypt_algos: (U8) {0x%02X, 0x%02X, 0x%02X, 0x%02X},\n"
         "                   sb_encrypt_pw_salt: (U8) {0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
         "                                             0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
         "                                             0x%02X, 0x%02X, 0x%02X, 0x%02X,\n"
         "                                             0x%02X, 0x%02X, 0x%02X, 0x%02X},\n"
         "                   sb_lost_and_found_inode: (U32) %u,\n"
         "                   sb_project_quota_inode: (U32) %u,\n"
         "                   sb_checksum_seed: (U32) %u,\n"
         "                   sb_first_error_code: %u,\n"
         "                   sb_last_error_code: %u,\n"
         "                   sb_encoding: ",
         le64toh(sb->sb_kilobytes_written),
         le32toh(sb->sb_error_count),
         first_error_time, str_first_error_time,
         le32toh(sb->sb_first_error_inode),
         le64toh(sb->sb_first_error_block),
         first_error_function,
         le32toh(sb->sb_first_error_line),
         last_error_time, str_last_error_time,
         le32toh(sb->sb_last_error_inode),
         le32toh(sb->sb_last_error_line),
         le64toh(sb->sb_last_error_block),
         last_error_function,
         mount_opts,
         le32toh(sb->sb_user_quota_inode),
         le32toh(sb->sb_group_quota_inode),
         le32toh(sb->sb_overhead_clusters),
         le32toh(sb->sb_backup_block_groups[0]),
         le32toh(sb->sb_backup_block_groups[1]),
         sb->sb_encrypt_algos[0], sb->sb_encrypt_algos[1],
         sb->sb_encrypt_algos[2], sb->sb_encrypt_algos[3],
         sb->sb_encrypt_pw_salt[0], sb->sb_encrypt_pw_salt[1],
         sb->sb_encrypt_pw_salt[2], sb->sb_encrypt_pw_salt[3],
         sb->sb_encrypt_pw_salt[4], sb->sb_encrypt_pw_salt[5],
         sb->sb_encrypt_pw_salt[6], sb->sb_encrypt_pw_salt[7],
         sb->sb_encrypt_pw_salt[8], sb->sb_encrypt_pw_salt[9],
         sb->sb_encrypt_pw_salt[10], sb->sb_encrypt_pw_salt[11],
         sb->sb_encrypt_pw_salt[12], sb->sb_encrypt_pw_salt[13],
         sb->sb_encrypt_pw_salt[14], sb->sb_encrypt_pw_salt[15],
         le32toh(sb->sb_lost_and_found_inode),
         le32toh(sb->sb_project_quota_inode),
         le32toh(sb->sb_checksum_seed),
         sb->sb_first_error_code,
         sb->sb_last_error_code);
  ext4fs_inspect_flag_names(le16toh(sb->sb_encoding),
                            ext4fs_encoding_names);
  printf(",\n"
         "                   sb_encoding_flags: ");
  ext4fs_inspect_flag_names(le16toh(sb->sb_encoding_flags),
                            ext4fs_encoding_flag_names);
  printf(",\n"
         "                   sb_orphan_file_inode: (U32) %u,\n"
         "                   sb_checksum: (U32) 0x%08X} # 0x%08X\n",
         le32toh(sb->sb_orphan_file_inode),
         checksum, checksum_computed);
  return 0;
}

uint64_t ext4fs_sb_block_group_count (const struct ext4fs_super_block *sb)
{
  uint32_t blocks_per_group;
  uint64_t count;
  assert(sb);
  count = le32toh(sb->sb_blocks_count_lo);
  if (ext4fs_64bit(sb))
    count |= (uint64_t) le32toh(sb->sb_blocks_count_hi) << 32;
  blocks_per_group = le32toh(sb->sb_blocks_per_group);
  count += blocks_per_group - 1;
  count /= blocks_per_group;
  return count;
}

int ext4fs_sb_block_size (const struct ext4fs_super_block *sb,
                          uint32_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = 1 << (sb->sb_log_block_size + 10);
  return 0;
}

int ext4fs_sb_blocks_count (const struct ext4fs_super_block *sb,
                            uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_blocks_count_hi) << 32;
  return 0;
}

int ext4fs_sb_check_time (const struct ext4fs_super_block *sb,
                          uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_check_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= ((uint64_t) sb->sb_check_time_hi) << 32;
  return 0;
}

int
ext4fs_sb_checksum_compute
(const struct ext4fs_super_block *sb,
 uint32_t *dest)
{
  uint32_t crc = 0;
  assert(sb);
  assert(dest);
  if (! (sb->sb_feature_ro_compat & EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM)) {
    *dest = 0;
    return 0;
  }
  crc = crc32c(crc, sb, offsetof(struct ext4fs_super_block, sb_checksum));
  *dest = ~crc;
  return 0;
}

int ext4fs_sb_first_error_time (const struct ext4fs_super_block *sb,
                             uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_first_error_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_first_error_time_hi << 32;
  return 0;
}

int ext4fs_sb_free_blocks_count (const struct ext4fs_super_block *sb,
                              uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_free_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_free_blocks_count_hi) << 32;
  return 0;
}

int ext4fs_sb_inode_size (const struct ext4fs_super_block *sb,
                          uint16_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le16toh(sb->sb_inode_size);
  return 0;
}

int ext4fs_sb_last_error_time (const struct ext4fs_super_block *sb,
                               uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_last_error_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_last_error_time_hi << 32;
  return 0;
}

int ext4fs_sb_mount_time (const struct ext4fs_super_block *sb,
                          uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_mount_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_mount_time_hi << 32;
  return 0;
}

int ext4fs_sb_newfs_time (const struct ext4fs_super_block *sb,
                          uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_newfs_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_newfs_time_hi << 32;
  return 0;
}

int ext4fs_sb_reserved_blocks_count (const struct ext4fs_super_block *sb,
                                     uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_reserved_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_reserved_blocks_count_hi) << 32;
  return 0;
}

int ext4fs_size (const char *dev, int fd, uint64_t *dest)
{
  assert(dev);
  assert(dest);
#if defined(OpenBSD)
  const char *dev_last;
  struct disklabel dl;
  struct partition *part;
  int32_t sector_size;
  if (! dev || ! dev[0]) {
    fprintf(stderr, "ext4fs_size: invalid dev\n");
    return -1;
  }
  if (! ext4fs_disklabel_get(&dl, fd))
    return -1;
  dev_last = dev + strlen(dev) - 1;
  if ('0' <= *dev_last && *dev_last <= '9')
    part = &dl.d_partitions[0];
  else if (*dev_last < 'a' || *dev_last > 'p') {
    fprintf(stderr, "ext4fs_size: %s: invalid partition letter", dev);
    return -1;
  }
  else
    part = &dl.d_partitions[*dev_last - 'a'];
  if (DL_GETPSIZE(part) == 0)
    fprintf(stderr, "ext4fs_size: %s: partition is unavailable", dev);
  sector_size = dl.d_secsize;
  if (sector_size <= 0) {
    fprintf(stderr, "ext4fs_size: %s: no sector size in disklabel", dev);
    return -1;
  }
  *dest = DL_GETPSIZE(part) / sector_size * sector_size;
#else
  if (ioctl(fd, BLKGETSIZE64, dest) < 0) {
    warn("%s: ioctl BLKGETSIZE64", dev);
    return -1;
  }
#endif
  return 0;
}

struct ext4fs_super_block *
ext4fs_super_block_read (struct ext4fs_super_block *sb,
                         int fd)
{
  ssize_t done;
  ssize_t r;
  ssize_t remaining;
  assert(sb);
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

int ext4fs_time_to_str (time_t time, char *str, size_t size)
{
  struct tm *local;
  assert(str);
  if (size < 25) {
    fprintf(stderr, "time_to_str: size < 25\n");
    return -1;
  }
  local = localtime(&time);
  if (! strftime(str, size, "%F %T %Z", local)) {
    fprintf(stderr, "time_to_str: strftime\n");
    return -1;
  }
  return 0;
}

int ext4fs_sb_write_time (const struct ext4fs_super_block *sb,
                          uint64_t *dest)
{
  assert(sb);
  assert(dest);
  *dest = le32toh(sb->sb_write_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_write_time_hi << 32;
  return 0;
}
