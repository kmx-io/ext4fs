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

#include <endian.h>
#include <err.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ext4fs.h>
#include <uuid.h>

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
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(gd->gd_block_bitmap_hi) << 32;
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
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_blocks_count_hi) << 32;
  return 0;
}

int ext4fs_check_time (const struct ext4fs_super_block *sb,
                       uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_check_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_check_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_check_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= ((uint64_t) sb->sb_check_time_hi) << 32;
  return 0;
}

#ifdef OpenBSD

struct disklabel *
ext4fs_disklabel_get (struct disklabel *dl, int fd)
{
  if (ioctl(fd, DIOCGDINFO, (char *) dl) == -1) {
    warn("disklabel_get: ioctl DIOCGDINFO");
    return NULL;
  }
  return dl;
}

#endif /* OpenBSD */

int ext4fs_first_error_time (const struct ext4fs_super_block *sb,
                             uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_first_error_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_first_error_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_first_error_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_first_error_time_hi << 32;
  return 0;
}

int ext4fs_free_blocks_count (const struct ext4fs_super_block *sb,
                              uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_free_blocks_count: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_free_blocks_count: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_free_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_free_blocks_count_hi) << 32;
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
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(gd->gd_inode_bitmap_hi) << 32;
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
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(gd->gd_inode_table_hi) << 32;
  return 0;
}

int ext4fs_inspect (const char *dev, int fd)
{
  struct ext4fs_group_desc gd = {0};
  struct ext4fs_super_block sb = {0};
  uint64_t size = 0;
  if (ext4fs_size(dev, fd, &size) ||
      ! size)
    return -1;
  printf("ext4fs_size: " CONFIGURE_FMT_UINT64 "\n", size);
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

void ext4fs_inspect_os (uint32_t os)
{
  if (os < sizeof(ext4fs_os_names) / sizeof(const char *) - 1)
    printf("%s", ext4fs_os_names[os]);
  else
    printf("(U32) %u", os);
}

int ext4fs_inspect_flag_names (uint32_t flags, const s_value_name *names)
{
  char first;
  const s_value_name *i;
  uint32_t remaining;
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
  printf("%%Ext4fs.GroupDesc{gd_block_bitmap: " CONFIGURE_FMT_UINT64 ",\n"
         "                  gd_inode_bitmap: " CONFIGURE_FMT_UINT64 ",\n"
         "                  gd_inode_table: " CONFIGURE_FMT_UINT64 "}\n",
         block_bitmap,
         inode_bitmap,
         inode_table);
  return 0;
}

int ext4fs_inspect_super_block (const struct ext4fs_super_block *sb)
{
  uint64_t blocks_count;
  uint64_t check_time;
  uint64_t first_error_time;
  char     first_error_function[EXT4FS_FUNCTION_MAX + 1] = {0};
  uint64_t free_blocks_count;
  char     last_error_function[EXT4FS_FUNCTION_MAX + 1] = {0};
  uint64_t last_error_time;
  char     last_mounted[EXT4FS_LAST_MOUNTED_MAX + 1] = {0};
  uint64_t mount_time;
  uint64_t newfs_time;
  uint64_t reserved_blocks_count;
  char str_check_time[32];
  char str_mount_time[32];
  char str_write_time[32];
  char str_newfs_time[32];
  char str_first_error_time[32];
  char str_last_error_time[32];
  char volume_name[EXT4FS_VOLUME_NAME_MAX + 1] = {0};
  uint64_t write_time;
  if (ext4fs_blocks_count(sb, &blocks_count) ||
      ext4fs_reserved_blocks_count(sb, &reserved_blocks_count) ||
      ext4fs_free_blocks_count(sb, &free_blocks_count) ||
      ext4fs_mount_time(sb, &mount_time) ||
      ext4fs_write_time(sb, &write_time) ||
      ext4fs_check_time(sb, &check_time) ||
      ext4fs_newfs_time(sb, &newfs_time) ||
      ext4fs_first_error_time(sb, &first_error_time) ||
      ext4fs_last_error_time(sb, &last_error_time) ||
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
                         sizeof(str_last_error_time)))
    return -1;
  strlcpy(volume_name, sb->sb_volume_name, sizeof(volume_name));
  strlcpy(last_mounted, sb->sb_last_mounted, sizeof(last_mounted));
  strlcpy(first_error_function, sb->sb_first_error_function,
          sizeof(first_error_function));
  strlcpy(last_error_function, sb->sb_last_error_function,
          sizeof(last_error_function));
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
         "                   sb_reserved_gdt_blocks: (U16) %u,\n"
         "                   sb_journal_uuid: ",
         volume_name,
         last_mounted,
         le32toh(sb->sb_algorithm_usage_bitmap),
         sb->sb_preallocate_blocks,
         sb->sb_preallocate_dir_blocks,
         le16toh(sb->sb_reserved_gdt_blocks));
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
         "                   sb_group_descriptor_size: (U16) %u,\n"
         "                   sb_default_mount_opts: ",
         le32toh(sb->sb_journal_inode_number),
         le32toh(sb->sb_journal_device_number),
         le32toh(sb->sb_last_orphan),
         sb->sb_hash_seed[0], sb->sb_hash_seed[1], sb->sb_hash_seed[2],
         sb->sb_hash_seed[3],
         sb->sb_default_hash_version,
         sb->sb_journal_backup_type,
         le16toh(sb->sb_group_descriptor_size));
  ext4fs_inspect_flag_names(le32toh(sb->sb_default_mount_opts),
                             ext4fs_mount_names);
  printf(",\n"
         "                   sb_first_meta_block_group: (U32) %u,\n"
         "                   sb_newfs_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_jnl_blocks: (U32) {0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x, 0x%08x,\n"
         "                                         0x%08x},\n"
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
         "                   sb_first_error_function: %s,\n"
         "                   sb_last_error_time: (U64) "
         CONFIGURE_FMT_UINT64 ",\t# %s\n"
         "                   sb_last_error_function: %s,\n"
         "                   }\n",
         le64toh(sb->sb_kilobytes_written),
         le32toh(sb->sb_error_count),
         first_error_time, str_first_error_time,
         le32toh(sb->sb_first_error_inode),
         le64toh(sb->sb_first_error_block),
         first_error_function,
         last_error_time, str_last_error_time,
         first_error_function);
  return 0;
}

int ext4fs_last_error_time (const struct ext4fs_super_block *sb,
                             uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_last_error_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_last_error_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_last_error_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_last_error_time_hi << 32;
  return 0;
}

int ext4fs_mount_time (const struct ext4fs_super_block *sb,
                       uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_mount_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_mount_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_mount_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_mount_time_hi << 32;
  return 0;
}

int ext4fs_newfs_time (const struct ext4fs_super_block *sb,
                       uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_newfs_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_newfs_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_newfs_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_newfs_time_hi << 32;
  return 0;
}

int ext4fs_reserved_blocks_count (const struct ext4fs_super_block *sb,
                                  uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_reserved_blocks_count: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_reserved_blocks_count: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_reserved_blocks_count_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) le32toh(sb->sb_reserved_blocks_count_hi) << 32;
  return 0;
}

int ext4fs_size (const char *dev, int fd, uint64_t *dest)
{
#if defined(OpenBSD)
  const char *dev_last;
  struct disklabel dl;
  struct partition *part;
  int32_t sector_size;
  if (! dev || ! dev[0]) {
    warnx("ext4fs_size: invalid dev");
    return -1;
  }
  if (! ext4fs_disklabel_get(&dl, fd))
    return -1;
  dev_last = dev + strlen(dev) - 1;
  if ('0' <= *dev_last && *dev_last <= '9')
    part = &dl.d_partitions[0];
  else if (*dev_last < 'a' || *dev_last > 'p') {
    warnx("ext4fs_size: %s: invalid partition letter", dev);
    return -1;
  }
  else
    part = &dl.d_partitions[*dev_last - 'a'];
  if (DL_GETPSIZE(part) == 0)
    warnx("ext4fs_size: %s: partition is unavailable", dev);
  sector_size = dl.d_secsize;
  if (sector_size <= 0) {
    warnx("ext4fs_size: %s: no sector size in disklabel", dev);
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
  if (size < 25) {
    warnx("time_to_str: size < 25");
    return -1;
  }
  local = localtime(&time);
  if (! strftime(str, size, "%F %T %Z", local)) {
    warnx("time_to_str: strftime");
    return -1;
  }
  return 0;
}

int ext4fs_write_time (const struct ext4fs_super_block *sb,
                       uint64_t *dest)
{
  if (! sb) {
    warnx("ext4fs_write_time: NULL super block");
    return -1;
  }
  if (! dest) {
    warnx("ext4fs_write_time: NULL dest");
    return -1;
  }
  *dest = le32toh(sb->sb_write_time_lo);
  if (ext4fs_64bit(sb))
    *dest |= (uint64_t) sb->sb_write_time_hi << 32;
  return 0;
}
