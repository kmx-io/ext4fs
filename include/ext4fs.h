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
#ifndef EXT4FS_H
#define EXT4FS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef struct {
  uint32_t value;
  const char *name;
} s_value_name;

#define EXT4FS_FUNCTION_MAX  32
#define EXT4FS_REV_DYNAMIC  1
#define EXT4FS_REV_MINOR  0
#define EXT4FS_LAST_MOUNTED_MAX  64
#define EXT4FS_MAGIC  0xEF53
#define EXT4FS_MOUNT_OPTS_MAX  64
#define EXT4FS_SUPER_BLOCK_OFFSET  1024
#define EXT4FS_SUPER_BLOCK_SIZE  1024
#define EXT4FS_VOLUME_NAME_MAX  16

#define EXT4FS_CHECKSUM_TYPE_NONE    0x0000
#define EXT4FS_CHECKSUM_TYPE_CRC32C  0x0001

extern const s_value_name ext4fs_checksum_type_names[];
     
#define EXT4FS_ENCODING_NONE  0x0000  // No encoding: legacy behavior
#define EXT4FS_ENCODING_UTF8  0x0001  // UTF-8 encoding, Unicode 12.1.0

extern const s_value_name ext4fs_encoding_names[];

#define EXT4FS_ENCODING_FLAG_NONE         0x0000
#define EXT4FS_ENCODING_FLAG_STRICT_MODE  0x0001  /* Reject invalid encoding */

extern const s_value_name ext4fs_encoding_flag_names[];

#define EXT4FS_ERRORS_CONTINUE  1  // Log and keep going
#define EXT4FS_ERRORS_RO        2  // Remount read-only
#define EXT4FS_ERRORS_PANIC     3  // Kernel panic

extern const char *ext4fs_error_policy_names[];

#define EXT4FS_FEATURE_COMPAT_DIR_PREALLOC   0x0001
#define EXT4FS_FEATURE_COMPAT_IMAGIC_INODES  0x0002
#define EXT4FS_FEATURE_COMPAT_HAS_JOURNAL    0x0004
#define EXT4FS_FEATURE_COMPAT_EXT_ATTR       0x0008
#define EXT4FS_FEATURE_COMPAT_RESIZE_INODE   0x0010
#define EXT4FS_FEATURE_COMPAT_DIR_INDEX      0x0020

extern const s_value_name ext4fs_feature_compat_names[];

#define EXT4FS_FEATURE_INCOMPAT_COMPRESSION  0x00001 // Not used
#define EXT4FS_FEATURE_INCOMPAT_FILETYPE     0x00002 // ftype in dirent
#define EXT4FS_FEATURE_INCOMPAT_RECOVER      0x00004 // needs journal recovery
#define EXT4FS_FEATURE_INCOMPAT_JOURNAL_DEV  0x00008 // External journal device
#define EXT4FS_FEATURE_INCOMPAT_META_BG      0x00010 // Meta block groups
#define EXT4FS_FEATURE_INCOMPAT_EXTENTS      0x00040 // Extents instead of block map
#define EXT4FS_FEATURE_INCOMPAT_64BIT        0x00080 // 64-bit block numbers
#define EXT4FS_FEATURE_INCOMPAT_MMP          0x00100 // Multiple mount protection
#define EXT4FS_FEATURE_INCOMPAT_FLEX_BG      0x00200 // Flexible block groups
#define EXT4FS_FEATURE_INCOMPAT_EA_INODE     0x00400 // In-inode xattrs
#define EXT4FS_FEATURE_INCOMPAT_DIRDATA      0x01000 // Inline dir data
#define EXT4FS_FEATURE_INCOMPAT_CSUM_SEED    0x02000 // Metadata checksum seed
#define EXT4FS_FEATURE_INCOMPAT_LARGEDIR     0x04000 // Large dir support
#define EXT4FS_FEATURE_INCOMPAT_INLINE_DATA  0x08000 // Inline file data
#define EXT4FS_FEATURE_INCOMPAT_ENCRYPT      0x10000 // File encryption

extern const s_value_name ext4fs_feature_incompat_names[];

#define EXT4FS_FEATURE_RO_COMPAT_SPARSE_SUPER   0x0001
#define EXT4FS_FEATURE_RO_COMPAT_LARGE_FILE     0x0002
#define EXT4FS_FEATURE_RO_COMPAT_BTREE_DIR      0x0004  // Not used in ext4
#define EXT4FS_FEATURE_RO_COMPAT_HUGE_FILE      0x0008
#define EXT4FS_FEATURE_RO_COMPAT_GDT_CSUM       0x0010
#define EXT4FS_FEATURE_RO_COMPAT_DIR_NLINK      0x0020
#define EXT4FS_FEATURE_RO_COMPAT_EXTRA_ISIZE    0x0040
#define EXT4FS_FEATURE_RO_COMPAT_HAS_SNAPSHOT   0x0080  // Unused
#define EXT4FS_FEATURE_RO_COMPAT_QUOTA          0x0100
#define EXT4FS_FEATURE_RO_COMPAT_BIGALLOC       0x0200
#define EXT4FS_FEATURE_RO_COMPAT_METADATA_CSUM  0x0400
#define EXT4FS_FEATURE_RO_COMPAT_REPLICA        0x0800  // Unused
#define EXT4FS_FEATURE_RO_COMPAT_READONLY       0x1000
#define EXT4FS_FEATURE_RO_COMPAT_PROJECT        0x2000

extern const s_value_name ext4fs_feature_ro_compat_names[];

#define EXT4FS_FLAG_SIGNED_HASH      0x0001  // Legacy hash uses signed ints
#define EXT4FS_FLAG_UNSIGNED_HASH    0x0002  // Default: unsigned directory hash
#define EXT4FS_FLAG_TEST_FILESYS     0x0004  // Marked as a test filesystem
#define EXT4FS_FLAG_64BIT            0x0008  // Uses 64-bit block numbers
#define EXT4FS_FLAG_MOUNT_OPT_CHECK  0x0010  // Kernel must check mount opts

extern const s_value_name ext4fs_flag_names[];

#define EXT4FS_INODE_BAD_BLOCKS    1
#define EXT4FS_INODE_ROOT_DIR      2
#define EXT4FS_INODE_USER_QUOTA    3
#define EXT4FS_INODE_GROUP_QUOTA   4
#define EXT4FS_INODE_BOOT_LOADER   5
#define EXT4FS_INODE_JOURNAL       8
#define EXT4FS_INODE_FIRST        11

extern const char *ext4fs_inode_names[];

#define EXTFS_INODE_FLAG_SECURE_RM                  0x00000001
#define EXTFS_INODE_FLAG_UN_RM                      0x00000002
#define EXTFS_INODE_FLAG_COMPRESSION                0x00000004
#define EXTFS_INODE_FLAG_SYNC                       0x00000008
#define EXTFS_INODE_FLAG_IMMUTABLE                  0x00000010
#define EXTFS_INODE_FLAG_APPEND                     0x00000020
#define EXTFS_INODE_FLAG_NO_DUMP                    0x00000040
#define EXTFS_INODE_FLAG_NO_ATIME                   0x00000080
#define EXTFS_INODE_FLAG_DIRTY                      0x00000100
#define EXTFS_INODE_FLAG_COMPRESSED_BLOCKS          0x00000200
#define EXTFS_INODE_FLAG_NO_COMPRESSION             0x00000400
#define EXTFS_INODE_FLAG_ENCRYPTED                  0x00000800
#define EXTFS_INODE_FLAG_INDEX                      0x00001000
#define EXTFS_INODE_FLAG_IMAGIC                     0x00002000
#define EXTFS_INODE_FLAG_JOURNAL_DATA               0x00004000
#define EXTFS_INODE_FLAG_NO_TAIL                    0x00008000
#define EXTFS_INODE_FLAG_DIR_SYNC                   0x00010000
#define EXTFS_INODE_FLAG_TOP_DIR                    0x00020000
#define EXTFS_INODE_FLAG_HUGE_FILE                  0x00040000
#define EXTFS_INODE_FLAG_EXTENTS                    0x00080000
#define EXTFS_INODE_FLAG_EXTENDED_ATTRIBUTES_INODE  0x00200000
#define EXTFS_INODE_FLAG_EOF_BLOCKS                 0x00400000
#define EXTFS_INODE_FLAG_INLINE_DATA                0x10000000
#define EXTFS_INODE_FLAG_PROJECT_ID_INHERITANCE     0x20000000
#define EXTFS_INODE_FLAG_CASEFOLD                   0x40000000

extern const s_value_name ext4fs_inode_flag_names[];

#define EXT4FS_MOUNT_READONLY              0x0001
#define EXT4FS_MOUNT_NO_ATIME              0x0002
#define EXT4FS_MOUNT_DIRSYNC               0x0004
#define EXT4FS_MOUNT_DATA_JOURNAL          0x0008
#define EXT4FS_MOUNT_DATA_ORDERED          0x0010
#define EXT4FS_MOUNT_DATA_WRITEBACK        0x0020
#define EXT4FS_MOUNT_ERRORS_CONTINUE       0x0040
#define EXT4FS_MOUNT_ERRORS_REMOUNT_RO     0x0080
#define EXT4FS_MOUNT_ERRORS_PANIC          0x0100
#define EXT4FS_MOUNT_DISCARD               0x0200
#define EXT4FS_MOUNT_NO_BUFFER_HEADS       0x0400
#define EXT4FS_MOUNT_SKIP_JOURNAL          0x0800
#define EXT4FS_MOUNT_NOAUTO_DELAYED_ALLOC  0x1000

extern const s_value_name ext4fs_mount_names[];

#define EXT4FS_OS_LINUX     0
#define EXT4FS_OS_HURD      1
#define EXT4FS_OS_MASIX     2
#define EXT4FS_OS_FREEBSD   3
#define EXT4FS_OS_LITES     4
#define EXT4FS_OS_OPENBSD   5

extern const char *ext4fs_os_str[];

#define EXT4FS_STATE_VALID  0x0001  // Clean unmount
#define EXT4FS_STATE_ERROR  0x0002  // Errors detected (fsck needed)

extern const s_value_name ext4fs_state_names[];

#define EXT4FS_BGD_FLAG_INODE_UNINIT     0x0001
#define EXT4FS_BGD_FLAG_BLOCK_UNINIT     0x0002
#define EXT4FS_BGD_FLAG_INODE_ZEROED     0x0004
#define EXT4FS_BGD_FLAG_DIRTY            0x0008
#define EXT4FS_BGD_FLAG_BLOCK_ZEROED     0x0010
#define EXT4FS_BGD_FLAG_READ_ONLY        0x0020

extern const s_value_name ext4fs_bgd_flag_names[];

struct ext4fs_super_block {
  uint32_t sb_inodes_count;
  uint32_t sb_blocks_count_lo;
  uint32_t sb_reserved_blocks_count_lo;
  uint32_t sb_free_blocks_count_lo;
  // 0x10
  uint32_t sb_free_inodes_count;
  uint32_t sb_first_data_block;
  uint32_t sb_log_block_size;       // log2(block size) - 10
  uint32_t sb_log_cluster_size;     // log2(cluster size) - 10
  // 0x20
  uint32_t sb_blocks_per_group;
  uint32_t sb_clusters_per_group;
  uint32_t sb_inodes_per_group;
  uint32_t sb_mount_time_lo;
  // 0x30
  uint32_t sb_write_time_lo;
  uint16_t sb_mount_count;
  int16_t  sb_max_mount_count_before_fsck;
  uint16_t sb_magic;
  uint16_t sb_state;                // EXT4FS_STATE_*
  uint16_t sb_errors;               // EXT4FS_ERRORS_*
  uint16_t sb_revision_level_minor;
  // 0x40
  uint32_t sb_check_time_lo;
  uint32_t sb_check_interval;
  uint32_t sb_creator_os;           // EXT4FS_OS_*
  uint32_t sb_revision_level;
  // 0x50
  uint16_t sb_default_reserved_uid;
  uint16_t sb_default_reserved_gid;
  uint32_t sb_first_non_reserved_inode;
  uint16_t sb_inode_size;
  uint16_t sb_block_group_id;
  uint32_t sb_feature_compat;
  // 0x60
  uint32_t sb_feature_incompat;
  uint32_t sb_feature_ro_compat;
  uint8_t  sb_uuid[16];
  char     sb_volume_name[EXT4FS_VOLUME_NAME_MAX];
  char     sb_last_mounted[EXT4FS_LAST_MOUNTED_MAX];
  uint32_t sb_algorithm_usage_bitmap;
  uint8_t  sb_preallocate_blocks;
  uint8_t  sb_preallocate_dir_blocks;
  uint16_t sb_reserved_bgdt_blocks;
  // 0xD0
  uint8_t  sb_journal_uuid[16];     // UUID of journal superblock
  // 0xE0
  uint32_t sb_journal_inode_number;
  uint32_t sb_journal_device_number;
  uint32_t sb_last_orphan;
  uint32_t sb_hash_seed[4];
  uint8_t  sb_default_hash_version;
  uint8_t  sb_journal_backup_type;
  uint16_t sb_block_group_descriptor_size;
  // 0x100
  uint32_t sb_default_mount_opts;
  uint32_t sb_first_meta_block_group;
  uint32_t sb_newfs_time_lo;
  uint32_t sb_jnl_blocks[17];       // Backup of journal inode
  // 0x150
  uint32_t sb_blocks_count_hi;
  uint32_t sb_reserved_blocks_count_hi;
  uint32_t sb_free_blocks_count_hi;
  uint16_t sb_inode_size_extra_min;
  uint16_t sb_inode_size_extra_want;
  // 0x160
  uint32_t sb_flags;
  uint16_t sb_raid_stride_block_count;
  uint16_t sb_mmp_interval;
  uint64_t sb_mmp_block;
  // 0x170
  uint32_t sb_raid_stripe_width_block_count;
  uint8_t  sb_log_groups_per_flex;
  uint8_t  sb_checksum_type;
  uint16_t sb_reserved_176;
  uint64_t sb_kilobytes_written;
  // 0x180
  uint32_t sb_ext3_snapshot_inode;
  uint32_t sb_ext3_snapshot_id;  
  uint64_t sb_ext3_snapshot_reserved_blocks_count;
  // 0x190
  uint32_t sb_ext3_snapshot_list;
  uint32_t sb_error_count;
  uint32_t sb_first_error_time_lo;
  uint32_t sb_first_error_inode;
  // 0x1A0
  uint64_t sb_first_error_block;
  char     sb_first_error_function[EXT4FS_FUNCTION_MAX];
  uint32_t sb_first_error_line;
  uint32_t sb_last_error_time_lo;
  // 0x1D0
  uint32_t sb_last_error_inode;
  uint32_t sb_last_error_line;
  uint64_t sb_last_error_block;
  // 0x1E0
  char     sb_last_error_function[EXT4FS_FUNCTION_MAX];
  // 0x200
  char     sb_mount_opts[EXT4FS_MOUNT_OPTS_MAX];
  // 0x240
  uint32_t sb_user_quota_inode;
  uint32_t sb_group_quota_inode;
  uint32_t sb_overhead_clusters;
  uint32_t sb_backup_block_groups[2];
  uint8_t  sb_encrypt_algos[4];
  uint8_t  sb_encrypt_pw_salt[16];
  uint32_t sb_lost_and_found_inode;
  uint32_t sb_project_quota_inode;
  // 0x270
  uint32_t sb_checksum_seed;
  uint8_t  sb_write_time_hi;
  uint8_t  sb_mount_time_hi;
  uint8_t  sb_newfs_time_hi;
  uint8_t  sb_check_time_hi;
  uint8_t  sb_first_error_time_hi;
  uint8_t  sb_last_error_time_hi;
  uint8_t  sb_first_error_code;
  uint8_t  sb_last_error_code;
  uint16_t sb_encoding;
  uint16_t sb_encoding_flags;
  // 0x280
  uint16_t sb_orphan_file_inode;
  uint16_t sb_reserved_284;
  uint32_t sb_reserved_288[94];
  uint32_t sb_checksum;
} __attribute__((packed));

struct ext4fs_block_group_descriptor {
  uint32_t bgd_block_bitmap_block_lo;
  uint32_t bgd_inode_bitmap_block_lo;
  uint32_t bgd_inode_table_block_lo;
  uint16_t bgd_free_blocks_count_lo;
  uint16_t bgd_free_inodes_count_lo;
  // 0x10
  uint16_t bgd_used_dirs_count_lo;
  uint16_t bgd_flags;
  uint32_t bgd_exclude_bitmap_block_lo;
  uint16_t bgd_block_bitmap_checksum_lo;
  uint16_t bgd_inode_bitmap_checksum_lo;
  uint16_t bgd_inode_table_unused_lo;
  uint16_t bgd_checksum;
  // 0x20
  uint32_t bgd_block_bitmap_block_hi;
  uint32_t bgd_inode_bitmap_block_hi;
  uint32_t bgd_inode_table_block_hi;
  uint16_t bgd_free_blocks_count_hi;
  uint16_t bgd_free_inodes_count_hi;
  // 0x30
  uint16_t bgd_used_dirs_count_hi;
  uint16_t bgd_inode_table_unused_hi;
  uint32_t bgd_exclude_bitmap_block_hi;
  uint16_t bgd_block_bitmap_checksum_hi;
  uint16_t bgd_inode_bitmap_checksum_hi;
  uint32_t bgd_reserved_3c;
  // 0x40
} __attribute__((packed));

#define EXT4FS_EXTENT_HEADER_MAGIC  0xF30A

struct ext4fs_extent_header {
  uint16_t eh_magic;
  uint16_t eh_entries;
  uint16_t eh_max;
  uint16_t eh_depth;
  uint32_t eh_generation;
} __attribute__((packed));

struct ext4fs_extent {
  uint32_t e_block;
  uint16_t e_len;
  uint16_t e_start_hi;
  uint32_t e_start_lo;
} __attribute__((packed));

struct ext4fs_extent_idx {
  uint32_t ei_block;
  uint32_t ei_leaf_lo;
  uint16_t ei_leaf_hi;
  uint16_t ei_unused;
} __attribute__((packed));

struct ext4fs_inode {
  uint16_t i_mode;
  uint16_t i_uid_lo;
  uint32_t i_size_lo;
  uint32_t i_atime;
  uint32_t i_ctime;
  // 0x10
  uint32_t i_mtime;
  uint32_t i_dtime;
  uint16_t i_gid_lo;
  uint16_t i_links_count;
  uint32_t i_blocks_lo;
  // 0x20
  uint32_t i_flags;
  uint32_t i_version;
  union {
    uint32_t i_block[15];
    struct {
      struct ext4fs_extent_header i_extent_header;
      union {
        struct ext4fs_extent i_extent[4];
        struct ext4fs_extent_idx i_extent_idx[4];
      };
    };
  };
  uint32_t i_nfs_generation;
  uint32_t i_extended_attributes_lo;
  uint32_t i_size_hi;
  // 0x70
  uint32_t i_fragment_address;
  uint16_t i_blocks_hi;
  uint16_t i_extended_attributes_hi;
  uint16_t i_uid_hi;
  uint16_t i_gid_hi;
  uint16_t i_checksum_lo;
  uint16_t i_reserved_7e;
  // 0x80
  uint16_t i_extra_isize;
  uint16_t i_checksum_hi;
  uint32_t i_ctime_extra;
  uint32_t i_mtime_extra;
  uint32_t i_atime_extra;
  // 0x90
  uint32_t i_crtime;
  uint32_t i_crtime_extra;
  uint32_t i_version_hi;
  uint32_t i_project_id;
  // 0xA0
} __attribute__((packed));

struct ext4fs_inode_256 {
  struct ext4fs_inode inode;
  uint8_t extended_attributes[256 - sizeof(struct ext4fs_inode)];
};

#define EXT4FS_EXTENT_DEPTH_MAX 5

struct ext4fs_extent_cursor {
  const struct ext4fs_super_block *sb;
  uint64_t inode_block;
  uint32_t inode_number;
  uint32_t inode_generation;
  struct {
    uint64_t physical_block;
    struct ext4fs_extent_header hdr;
    uint16_t idx;
    uint64_t block_number;
  } stack[EXT4FS_EXTENT_DEPTH_MAX + 1];
  uint64_t block_offset;
  short depth;
  uint64_t offset;
  int eof;
};

int
ext4fs_bgd_block_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest);

int
ext4fs_bgd_block_bitmap_checksum
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

int
ext4fs_bgd_checksum_compute
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t block_group_id, uint16_t *dest);

int
ext4fs_bgd_exclude_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest);

int
ext4fs_bgd_free_blocks_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

int
ext4fs_bgd_free_inodes_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

int
ext4fs_bgd_inode_bitmap_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest);

int
ext4fs_bgd_inode_bitmap_checksum
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

int
ext4fs_bgd_inode_table_block
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint64_t *dest);

int
ext4fs_bgd_inode_table_unused
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

int
ext4fs_bgd_used_dirs_count
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t *dest);

#ifdef OpenBSD

struct disklabel *
ext4fs_disklabel_get
(struct disklabel *dl, int fd);

#endif // OpenBSD

struct ext4fs_block_group_descriptor *
ext4fs_block_group_descriptor_read
(const struct ext4fs_super_block *sb,
 struct ext4fs_block_group_descriptor *bgd,
 uint64_t bgd_count,
 int fd);

int ext4fs_extent_start
(const struct ext4fs_extent *extent,
 uint64_t *start);

int
ext4fs_inode_256_checksum_compute
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode_256 *inode,
 uint32_t inode_number,
 uint32_t *dest);

struct ext4fs_inode_256 *
ext4fs_inode_256_read
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 struct ext4fs_inode_256 *inode, 
 uint32_t inode_number,
 int fd);

int
ext4fs_inode_blocks
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest);

int
ext4fs_inode_extended_attributes
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest);

int
ext4fs_inode_gid
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint32_t *dest);

int
ext4fs_inode_size
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint64_t *dest);

int
ext4fs_inode_uid
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode *inode,
 uint32_t *dest);

int
ext4fs_inspect
(const char *dev,
 int fd);

int
ext4fs_inspect_block_group_descriptor
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd,
 uint32_t block_group_id);

int
ext4fs_inspect_block_group_descriptor_hex
(const struct ext4fs_super_block *sb,
 const struct ext4fs_block_group_descriptor *bgd);

void
ext4fs_inspect_creator_os
(uint16_t creator_os);

void
ext4fs_inspect_errors
(uint16_t errors);

int
ext4fs_inspect_extent
(const struct ext4fs_extent *extent,
 uint8_t indent);

int
ext4fs_inspect_extent_header
(const struct ext4fs_extent_header *eh,
 uint8_t indent);

int
ext4fs_inspect_flag_names
(uint32_t flags,
 const s_value_name *names);

int
ext4fs_inspect_inode_256
(const struct ext4fs_super_block *sb,
 const struct ext4fs_inode_256 *inode,
 uint32_t inode_number);

int
ext4fs_inspect_super_block
(const struct ext4fs_super_block *sb);

int
ext4fs_mode_to_str
(uint16_t mode,
 char *dest,
 size_t size);

uint64_t
ext4fs_sb_block_group_count
(const struct ext4fs_super_block *sb);

int
ext4fs_sb_checksum_compute
(const struct ext4fs_super_block *sb,
                                uint32_t *dest);

int
ext4fs_sb_last_error_time
(const struct ext4fs_super_block *sb,
                            uint64_t *dest);

int
ext4fs_sb_block_size
(const struct ext4fs_super_block *sb,
                          uint32_t *dest);

int
ext4fs_sb_blocks_count
(const struct ext4fs_super_block *sb,
                            uint64_t *dest);

int
ext4fs_sb_check_time
(const struct ext4fs_super_block *sb,
                          uint64_t *dest);

int
ext4fs_sb_first_error_time
(const struct ext4fs_super_block *sb,
                                uint64_t *dest);

int
ext4fs_sb_free_blocks_count
(const struct ext4fs_super_block *sb,
                                 uint64_t *dest);

int
ext4fs_sb_inode_size
(const struct ext4fs_super_block *sb,
                          uint16_t *dest);

int
ext4fs_sb_mount_time
(const struct ext4fs_super_block *sb,
                          uint64_t *dest);

int
ext4fs_sb_newfs_time
(const struct ext4fs_super_block *sb,
                          uint64_t *dest);

int
ext4fs_sb_reserved_blocks_count
(const struct ext4fs_super_block *sb,
                                     uint64_t *dest);

int
ext4fs_sb_write_time
(const struct ext4fs_super_block *sb,
                          uint64_t *dest);

int
ext4fs_size
(const char *dev,
 int fd,
 uint64_t *dest);

struct ext4fs_super_block *
ext4fs_super_block_read
(struct ext4fs_super_block *sb,
                         int fd);

int
ext4fs_time_to_str
(time_t time,
 char *str,
 size_t size);

#endif /* EXT4FS_H */
