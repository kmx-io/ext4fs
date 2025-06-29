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
#ifndef EXT4FS_H
#define EXT4FS_H

#include <stdint.h>

typedef struct {
  uint32_t value;
  const char *name;
} s_enum;

#define EXT4FS_DYNAMIC_REV 1
#define EXT4FS_DYNAMIC_REV_MINOR 0
#define EXT4FS_MAGIC 0xEF53
#define EXT4FS_SUPER_BLOCK_OFFSET 1024
#define EXT4FS_SUPER_BLOCK_SIZE 1024
#define EXT4FS_VALID_FS 1

#define EXT4FS_ERRORS_CONTINUE 1

#define EXT4FS_FEATURE_COMPAT_DIR_PREALLOC   0x0001
#define EXT4FS_FEATURE_COMPAT_IMAGIC_INODES  0x0002
#define EXT4FS_FEATURE_COMPAT_HAS_JOURNAL    0x0004
#define EXT4FS_FEATURE_COMPAT_EXT_ATTR       0x0008
#define EXT4FS_FEATURE_COMPAT_RESIZE_INODE   0x0010
#define EXT4FS_FEATURE_COMPAT_DIR_INDEX      0x0020

s_enum ext4fs_feature_compat[] = {
  {EXT4FS_FEATURE_COMPAT_DIR_PREALLOC,  "dir_prealloc"},
  {EXT4FS_FEATURE_COMPAT_IMAGIC_INODES, "imagic_inodes"},
  {EXT4FS_FEATURE_COMPAT_HAS_JOURNAL,   "has_journal"},
  {EXT4FS_FEATURE_COMPAT_EXT_ATTR,      "ext_attr"},
  {EXT4FS_FEATURE_COMPAT_RESIZE_INODE,  "resize_inode"},
  {EXT4FS_FEATURE_COMPAT_DIR_INDEX,     "dir_index"},
  {0,                                   NULL}
};

#define EXT4FS_FEATURE_INCOMPAT_COMPRESSION  0x00001 // Not used in ext4
#define EXT4FS_FEATURE_INCOMPAT_FILETYPE     0x00002 // Directory entry has type
#define EXT4FS_FEATURE_INCOMPAT_RECOVER      0x00004 // Needs journal replay
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

s_enum ext4fs_feature_incompat[] = {
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
  {0,                                   NULL}
};

#define EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER   0x0001
#define EXT4_FEATURE_RO_COMPAT_LARGE_FILE     0x0002
#define EXT4_FEATURE_RO_COMPAT_BTREE_DIR      0x0004  // Not used in ext4
#define EXT4_FEATURE_RO_COMPAT_HUGE_FILE      0x0008
#define EXT4_FEATURE_RO_COMPAT_GDT_CSUM       0x0010
#define EXT4_FEATURE_RO_COMPAT_DIR_NLINK      0x0020
#define EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE    0x0040
#define EXT4_FEATURE_RO_COMPAT_HAS_SNAPSHOT   0x0080  // Unused
#define EXT4_FEATURE_RO_COMPAT_QUOTA          0x0100
#define EXT4_FEATURE_RO_COMPAT_BIGALLOC       0x0200
#define EXT4_FEATURE_RO_COMPAT_METADATA_CSUM  0x0400
#define EXT4_FEATURE_RO_COMPAT_REPLICA        0x0800  // Unused
#define EXT4_FEATURE_RO_COMPAT_READONLY       0x1000
#define EXT4_FEATURE_RO_COMPAT_PROJECT        0x2000

s_enum ext4fs_feature_ro_compat[] = {
  {EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER,  "sparse_super"},
  {EXT4_FEATURE_RO_COMPAT_LARGE_FILE,    "large_file"},
  {EXT4_FEATURE_RO_COMPAT_BTREE_DIR,     "btree_dir"},
  {EXT4_FEATURE_RO_COMPAT_HUGE_FILE,     "huge_file"},
  {EXT4_FEATURE_RO_COMPAT_GDT_CSUM,      "gdt_csum"},
  {EXT4_FEATURE_RO_COMPAT_DIR_NLINK,     "dir_nlink"},
  {EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE,   "extra_isize"},
  {EXT4_FEATURE_RO_COMPAT_HAS_SNAPSHOT,  "has_snapshot"},
  {EXT4_FEATURE_RO_COMPAT_QUOTA,         "quota"},
  {EXT4_FEATURE_RO_COMPAT_BIGALLOC,      "bigalloc"},
  {EXT4_FEATURE_RO_COMPAT_METADATA_CSUM, "metadata_csum"},
  {EXT4_FEATURE_RO_COMPAT_REPLICA,       "replica"},
  {EXT4_FEATURE_RO_COMPAT_READONLY,      "readonly"},
  {EXT4_FEATURE_RO_COMPAT_PROJECT,       "project"},
  {0,                                    NULL}
};

#define EXT4FS_OS_LINUX     0
#define EXT4FS_OS_HURD      1
#define EXT4FS_OS_MASIX     2
#define EXT4FS_OS_FREEBSD   3
#define EXT4FS_OS_LITES     4
#define EXT4FS_OS_OPENBSD   5

struct ext4fs_super_block {
    uint32_t sb_inodes_count;
    uint32_t sb_blocks_count_lo;
    uint32_t sb_reserved_blocks_count_lo;
    uint32_t sb_free_blocks_count_lo;
    uint32_t sb_free_inodes_count;
    uint32_t sb_first_data_block;
    uint32_t sb_log_block_size;       // log2(block size) - 10
    uint32_t sb_log_cluster_size;     // log2(cluster size) - 10
    uint32_t sb_blocks_per_group;
    uint32_t sb_clusters_per_group;
    uint32_t sb_inodes_per_group;
    uint32_t sb_mtime;                // Mount time
    uint32_t sb_wtime;                // Write time
    uint16_t sb_mnt_count;            // Mount count
    uint16_t sb_max_mnt_count;        // Max mount count before fsck
    uint16_t sb_magic;                // Magic signature
    uint16_t sb_state;                // File system state
    uint16_t sb_errors;               // Behaviour when detecting errors
    uint16_t sb_rev_level_minor;      // Minor revision level
    uint32_t sb_lastcheck;            // Last check time
    uint32_t sb_checkinterval;        // Max time between checks
    uint32_t sb_creator_os;           // OS
    uint32_t sb_rev_level;            // Revision level
    uint16_t sb_def_resuid;           // Default uid for reserved blocks
    uint16_t sb_def_resgid;           // Default gid for reserved blocks

    // EXT4_DYNAMIC_REV Specific:
    uint32_t sb_first_ino;            // First non-reserved inode
    uint16_t sb_inode_size;           // Inode size
    uint16_t sb_block_group_nr;       // Block group # of this superblock
    uint32_t sb_feature_compat;       // Compatible feature set
    uint32_t sb_feature_incompat;     // Incompatible feature set
    uint32_t sb_feature_ro_compat;    // Read-only compatible feature set
    uint8_t  sb_uuid[16];             // 128-bit filesystem UUID
    char     sb_volume_name[16];      // Volume name
    char     sb_last_mounted[64];     // Directory where last mounted
    uint32_t sb_algorithm_usage_bitmap; // For compression (unused)

    // Journaling support:
    uint8_t  sb_journal_uuid[16];     // UUID of journal superblock
    uint32_t sb_journal_inum;         // Inode number of journal file
    uint32_t sb_journal_dev;          // Device number of journal file
    uint32_t sb_last_orphan;          // Start of orphan inode list

    uint32_t sb_hash_seed[4];         // HTREE hash seed
    uint8_t  sb_def_hash_version;     // Default hash version
    uint8_t  sb_jnl_backup_type;
    uint16_t sb_desc_size;            // Group descriptor size
    uint32_t sb_default_mount_opts;
    uint32_t sb_first_meta_bg;        // First metablock block group
    uint32_t sb_mkfs_time;            // When the FS was created
    uint32_t sb_jnl_blocks[17];       // Backup of journal inode

    // 64-bit support:
    uint32_t sb_blocks_count_hi;
    uint32_t sb_reserved_blocks_count_hi;
    uint32_t sb_free_blocks_count_hi;
    uint16_t sb_min_extra_isize;
    uint16_t sb_want_extra_isize;
    uint32_t sb_flags;
    uint16_t sb_raid_stride;
    uint16_t sb_mmp_interval;
    uint64_t sb_mmp_block;
    uint32_t sb_raid_stripe_width;
    uint8_t  sb_log_groups_per_flex;
    uint8_t  sb_checksum_type;
    uint16_t sb_reserved_pad;
    uint64_t sb_kbytes_written;
    uint32_t sb_snapshot_inum;
    uint32_t sb_snapshot_id;
    uint64_t sb_snapshot_r_blocks_count;
    uint32_t sb_snapshot_list;

    // Error handling:
    uint32_t sb_error_count;
    uint32_t sb_first_error_time;
    uint32_t sb_first_error_ino;
    uint64_t sb_first_error_block;
    uint8_t  sb_first_error_func[32];
    uint32_t sb_first_error_line;
    uint32_t sb_last_error_time;
    uint32_t sb_last_error_ino;
    uint32_t sb_last_error_line;
    uint64_t sb_last_error_block;
    uint8_t  sb_last_error_func[32];

    uint8_t  sb_mount_opts[64];
    uint32_t sb_usr_quota_inum;
    uint32_t sb_grp_quota_inum;
    uint32_t sb_overhead_blocks;
    uint32_t sb_backup_bgs[2];
    uint8_t  sb_encrypt_algos[4];
    uint8_t  sb_encrypt_pw_salt[16];
    uint32_t sb_lpf_ino;
    uint32_t sb_prj_quota_inum;
    uint32_t sb_checksum_seed;

    uint8_t  sb_wtime_hi;
    uint8_t  sb_mtime_hi;
    uint8_t  sb_mkfs_time_hi;
    uint8_t  sb_lastcheck_hi;
    uint8_t  sb_first_error_time_hi;
    uint8_t  sb_last_error_time_hi;
    uint8_t  sb_pad[2];
    uint32_t sb_reserved[96];

    uint32_t sb_checksum;             // Superblock checksum
} __attribute__((packed));

struct ext4fs_group_desc {
    uint32_t gd_block_bitmap_lo;   // Block ID of block bitmap
    uint32_t gd_inode_bitmap_lo;   // Block ID of inode bitmap
    uint32_t gd_inode_table_lo;    // Starting block of inode table
    uint16_t gd_free_blocks_count; // Free blocks in this group
    uint16_t gd_free_inodes_count; // Free inodes in this group
    uint16_t gd_used_dirs_count;   // Number of directories in this group
    uint16_t gd_flags;
    uint32_t gd_exclude_bitmap_lo; // Optional (sparse allocation)
    uint16_t gd_block_bitmap_csum;
    uint16_t gd_inode_bitmap_csum;
    uint16_t gd_itable_unused;
    uint16_t gd_checksum;
    uint32_t gd_block_bitmap_hi;
    uint32_t gd_inode_bitmap_hi;
    uint32_t gd_inode_table_hi;
    uint16_t gd_free_blocks_count_hi;
    uint16_t gd_free_inodes_count_hi;
    uint16_t gd_used_dirs_count_hi;
    uint16_t gd_itable_unused_hi;
    uint32_t gd_exclude_bitmap_hi;
    uint16_t gd_block_bitmap_csum_hi;
    uint16_t gd_inode_bitmap_csum_hi;
    uint32_t gd_reserved;
} __attribute__((packed));

int ext4fs_block_bitmap (const struct ext4fs_super_block *sb,
                         const struct ext4fs_group_desc *gd,
                         uint64_t *dest);

int ext4fs_block_size (const struct ext4fs_super_block *sb,
                       uint32_t *dest);

struct ext4fs_group_desc *
ext4fs_group_desc_read (struct ext4fs_group_desc *gd,
                        int fd,
                        const struct ext4fs_super_block *sb);

int ext4fs_inode_bitmap (const struct ext4fs_super_block *sb,
                         const struct ext4fs_group_desc *gd,
                         uint64_t *dest);

int ext4fs_inode_table (const struct ext4fs_super_block *sb,
                        const struct ext4fs_group_desc *gd,
                        uint64_t *dest);

int ext4fs_inspect (int fd);

int ext4fs_inspect_group_desc (const struct ext4fs_super_block *sb,
                               const struct ext4fs_group_desc *gd);

int ext4fs_inspect_super_block (const struct ext4fs_super_block *sb);

int ext4fs_size (int fd, uint64_t *dest);

struct ext4fs_super_block *
ext4fs_super_block_read (struct ext4fs_super_block *sb,
                         int fd);

#endif /* EXT4FS_H */
