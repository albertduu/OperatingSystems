/*
 *  Copyright (C) 2025 CS416 Rutgers CS
 *	Rutgers Tiny File System
 *	File:	rufs.c
 *
 */

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <sys/time.h>
#include <libgen.h>
#include <limits.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>

#include "block.h"
#include "rufs.h"

#define NUM_DIRENT_ENTRIES (BLOCK_SIZE / sizeof(struct dirent))

char diskfile_path[PATH_MAX];

struct superblock g_superblock;
char g_superblock_set = 0;

int get_avail_ino(void);
int get_avail_blkno(void);
int readi(uint16_t ino, struct inode *inode);
int writei(uint16_t ino, struct inode *inode);
int dir_find(uint16_t ino, const char *fname, size_t name_len, struct dirent *dirent);
int dir_add(struct inode dir_inode, uint16_t f_ino, const char *fname, size_t name_len);
int get_node_by_path(const char *path, uint16_t ino, struct inode *inode);

static int create_root() {
    struct inode root_inode;
    memset(&root_inode, 0, sizeof(root_inode));

    root_inode.ino   = 0;
    root_inode.valid = 1;
    root_inode.size  = 0;
    root_inode.type  = S_IFDIR;
    root_inode.link  = 1;             

    for (int i = 0; i < 16; i++) root_inode.direct_ptr[i] = 0;
    for (int i = 0; i < 8; i++)  root_inode.indirect_ptr[i] = 0;

    root_inode.vstat.st_ino  = root_inode.ino;
    root_inode.vstat.st_mode = S_IFDIR | 0755;
    root_inode.vstat.st_nlink = 1;
    root_inode.vstat.st_uid = getuid();
    root_inode.vstat.st_gid = getgid();
    root_inode.vstat.st_size = 0;
    root_inode.vstat.st_blksize = BLOCK_SIZE;
    root_inode.vstat.st_blocks  = 0;

    time_t now;
    time(&now);
    root_inode.vstat.st_atime = now;
    root_inode.vstat.st_mtime = now;
    root_inode.vstat.st_ctime = now;

    int blk_index = get_avail_blkno();
    if (blk_index < 0) return -1;

    root_inode.direct_ptr[0] = blk_index;
    root_inode.vstat.st_blocks++;

    char block_data[BLOCK_SIZE];
    memset(block_data, 0, BLOCK_SIZE);

    struct dirent *entry = (struct dirent *)block_data;

    entry[0].valid = 1;
    entry[0].ino   = 0;
    strcpy(entry[0].name, ".");
    entry[0].len   = (uint16_t)strlen(entry[0].name);

    entry[1].valid = 1;
    entry[1].ino   = 0;
    strcpy(entry[1].name, "..");
    entry[1].len   = (uint16_t)strlen(entry[1].name);

    bio_write(g_superblock.d_start_blk + blk_index, block_data);

    root_inode.size          = 2 * sizeof(struct dirent);
    root_inode.vstat.st_size = root_inode.size;
    root_inode.vstat.st_nlink = 2;

    writei(root_inode.ino, &root_inode);
    return 0;
}

/* 
 * Get available inode number from bitmap
 */
int get_avail_ino(void) {
    assert(g_superblock_set == 1);

    unsigned char i_bitmap[BLOCK_SIZE];
    memset(i_bitmap, 0, BLOCK_SIZE);
    bio_read(g_superblock.i_bitmap_blk, i_bitmap);

    for (int i = 0; i < BLOCK_SIZE * 8 && i < g_superblock.max_inum; i++) {
        if (get_bitmap((bitmap_t)i_bitmap, i) == 0) {
            set_bitmap((bitmap_t)i_bitmap, i);
            bio_write(g_superblock.i_bitmap_blk, i_bitmap);
            return i;
        }
    }

    perror("get_avail_ino: no free inode");
    return -1;
}

/* 
 * Get available data block number from bitmap
 */
int get_avail_blkno(void) {
    assert(g_superblock_set == 1);

    unsigned char d_bitmap[BLOCK_SIZE];
    memset(d_bitmap, 0, BLOCK_SIZE);
    bio_read(g_superblock.d_bitmap_blk, d_bitmap);

    for (int i = 0; i < BLOCK_SIZE * 8 && i < g_superblock.max_dnum; i++) {
        if (get_bitmap((bitmap_t)d_bitmap, i) == 0) {
            set_bitmap((bitmap_t)d_bitmap, i);
            bio_write(g_superblock.d_bitmap_blk, d_bitmap);
            return i; 
        }
    }

    perror("get_avail_blkno: no free data block");
    return -1;
}

/* 
 * inode operations
 */
int readi(uint16_t ino, struct inode *inode) {
    int blk = g_superblock.i_start_blk + (ino * (int)sizeof(struct inode)) / BLOCK_SIZE;
    int offset = (ino * (int)sizeof(struct inode)) % BLOCK_SIZE;

    char buf[BLOCK_SIZE];
    bio_read(blk, buf);
    memcpy(inode, buf + offset, sizeof(struct inode));
    return 0;
}

int writei(uint16_t ino, struct inode *inode) {
    int blk = g_superblock.i_start_blk + (ino * (int)sizeof(struct inode)) / BLOCK_SIZE;
    int offset = (ino * (int)sizeof(struct inode)) % BLOCK_SIZE;

    char buf[BLOCK_SIZE];
    bio_read(blk, buf);
    memcpy(buf + offset, inode, sizeof(struct inode));
    bio_write(blk, buf);
    return 0;
}

/* 
 * directory operations
 */
int dir_find(uint16_t ino, const char *fname, size_t name_len, struct dirent *dirent) {
    struct inode dir_inode;

    if (readi(ino, &dir_inode) < 0) return -1;

    char block_data[BLOCK_SIZE];
    for (int i = 0; i < 16; i++) {
        if (dir_inode.direct_ptr[i] == 0) continue;

        int blk = g_superblock.d_start_blk + dir_inode.direct_ptr[i];
        if (bio_read(blk, block_data) < 0) return -1;

        struct dirent *entries = (struct dirent *)block_data;
        for (int j = 0; j < NUM_DIRENT_ENTRIES; j++) {
            if (entries[j].valid &&
                entries[j].len == (uint16_t)name_len &&
                strncmp(entries[j].name, fname, name_len) == 0) {
                *dirent = entries[j];
                return 0;
            }
        }
    }
    return -1;
}

int dir_add(struct inode dir_inode, uint16_t f_ino, const char *fname, size_t name_len) {
    struct dirent existing;
    if (dir_find(dir_inode.ino, fname, name_len, &existing) == 0) {
        return -1;
    }

    char block_data[BLOCK_SIZE];

    for (int i = 0; i < 16; i++) {

        if (dir_inode.direct_ptr[i] == 0) {
            int new_blk = get_avail_blkno();
            if (new_blk < 0) return -1;
            dir_inode.direct_ptr[i] = new_blk;
            memset(block_data, 0, BLOCK_SIZE);
            dir_inode.vstat.st_blocks++;
        } else {
            int blk = g_superblock.d_start_blk + dir_inode.direct_ptr[i];
            bio_read(blk, block_data);
        }

        struct dirent *entries = (struct dirent *)block_data;
        for (int j = 0; j < NUM_DIRENT_ENTRIES; j++) {
            if (!entries[j].valid) {
                entries[j].valid = 1;
                entries[j].ino = f_ino;
                memset(entries[j].name, 0, sizeof(entries[j].name));
                memcpy(entries[j].name, fname, name_len);
                entries[j].name[name_len] = '\0';
                entries[j].len = (uint16_t)name_len;

                dir_inode.size += sizeof(struct dirent);
                dir_inode.vstat.st_size = dir_inode.size;
                time(&dir_inode.vstat.st_mtime);

                writei(dir_inode.ino, &dir_inode);
                int blk = g_superblock.d_start_blk + dir_inode.direct_ptr[i];
                bio_write(blk, block_data);
                return 0;
            }
        }
    }

    return -1; 
}

/* 
 * namei operation
 */
int get_node_by_path(const char *path, uint16_t ino, struct inode *inode) {
    if (path == NULL || strlen(path) == 0) return -1;

    uint16_t curr_ino = (path[0] == '/') ? 0 : ino;

    if (strcmp(path, "/") == 0) {
        return readi(curr_ino, inode);
    }

    char path_copy[PATH_MAX];
    strncpy(path_copy, path, PATH_MAX - 1);
    path_copy[PATH_MAX - 1] = '\0';

    char *token = strtok(path_copy, "/");
    struct inode curr_inode;
    struct dirent dent;

    while (token != NULL) {
        if (readi(curr_ino, &curr_inode) < 0) return -1;
        if (dir_find(curr_ino, token, strlen(token), &dent) < 0) return -ENOENT;

        curr_ino = dent.ino;
        token = strtok(NULL, "/");
    }

    if (readi(curr_ino, inode) < 0) return -1;
    return 0;
}

/* 
 * Make file system
 */
int rufs_mkfs(void) {
    dev_init(diskfile_path);

    memset(&g_superblock, 0, sizeof(g_superblock));
    g_superblock.magic_num    = MAGIC_NUM;
    g_superblock.max_inum     = MAX_INUM;
    g_superblock.max_dnum     = MAX_DNUM;
    g_superblock.i_bitmap_blk = 1;
    g_superblock.d_bitmap_blk = 2;
    g_superblock.i_start_blk  = 3;

    int inode_region_blocks =
        (MAX_INUM * (int)sizeof(struct inode) + BLOCK_SIZE - 1) / BLOCK_SIZE;
    g_superblock.d_start_blk = g_superblock.i_start_blk + inode_region_blocks;

    char sb_block[BLOCK_SIZE];
    memset(sb_block, 0, BLOCK_SIZE);
    memcpy(sb_block, &g_superblock, sizeof(struct superblock));
    bio_write(0, sb_block);

    g_superblock_set = 1;

    unsigned char i_bitmap[BLOCK_SIZE];
    unsigned char d_bitmap[BLOCK_SIZE];
    memset(i_bitmap, 0, BLOCK_SIZE);
    memset(d_bitmap, 0, BLOCK_SIZE);

    bio_write(g_superblock.i_bitmap_blk, i_bitmap);
    bio_write(g_superblock.d_bitmap_blk, d_bitmap);

    create_root();

    set_bitmap((bitmap_t)i_bitmap, 0);
    bio_write(g_superblock.i_bitmap_blk, i_bitmap);

    return 0;
}

/* 
 * FUSE file operations
 */
static void *rufs_init(struct fuse_conn_info *conn) {
    (void)conn;

    if (dev_open(diskfile_path) < 0) {
        rufs_mkfs();
    } else {
        char sb_block[BLOCK_SIZE];
        bio_read(0, sb_block);
        memcpy(&g_superblock, sb_block, sizeof(struct superblock));
        g_superblock_set = 1;
    }
    return NULL;
}

static void rufs_destroy(void *userdata) {
    (void)userdata;
    dev_close();
}

static int rufs_getattr(const char *path, struct stat *stbuf) {
    struct inode inode;
    int ret = get_node_by_path(path, 0, &inode);
    if (ret < 0) return ret;
    *stbuf = inode.vstat;
    return 0;
}

static int rufs_opendir(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    struct inode dir_inode;
    int ret = get_node_by_path(path, 0, &dir_inode);
    if (ret < 0) return ret;
    if (!dir_inode.valid) return -ENOENT;
    if ((dir_inode.vstat.st_mode & S_IFMT) != S_IFDIR) return -ENOTDIR;
    return 0;
}

static int rufs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
                        off_t offset, struct fuse_file_info *fi) {
    (void)offset;
    (void)fi;

    struct inode dir_inode;
    if (get_node_by_path(path, 0, &dir_inode) < 0) return -ENOENT;

    char block_data[BLOCK_SIZE];
    for (int i = 0; i < 16; i++) {
        if (dir_inode.direct_ptr[i] == 0) continue;

        int blk = g_superblock.d_start_blk + dir_inode.direct_ptr[i];
        if (bio_read(blk, block_data) < 0) continue;

        struct dirent *entries = (struct dirent *)block_data;
        for (int j = 0; j < NUM_DIRENT_ENTRIES; j++) {
            if (entries[j].valid) {
                struct inode entry_inode;
                readi(entries[j].ino, &entry_inode);
                filler(buffer, entries[j].name, &entry_inode.vstat, 0);
            }
        }
    }
    return 0;
}

static int rufs_mkdir(const char *path, mode_t mode) {
    struct inode parent_inode, new_dir_inode;

    char parent_path[PATH_MAX];
    char name_copy[PATH_MAX];

    strncpy(parent_path, path, PATH_MAX - 1);
    parent_path[PATH_MAX - 1] = '\0';
    strncpy(name_copy, path, PATH_MAX - 1);
    name_copy[PATH_MAX - 1] = '\0';

    char *dir_name = basename(name_copy);
    dirname(parent_path);

    if (get_node_by_path(parent_path, 0, &parent_inode) < 0) return -ENOENT;

    int new_ino = get_avail_ino();
    if (new_ino < 0) return -ENOSPC;

    if (dir_add(parent_inode, (uint16_t)new_ino, dir_name, strlen(dir_name)) < 0)
        return -1;

    memset(&new_dir_inode, 0, sizeof(new_dir_inode));
    new_dir_inode.ino = (uint16_t)new_ino;
    new_dir_inode.valid = 1;
    new_dir_inode.size = 0;
    new_dir_inode.type = S_IFDIR;
    new_dir_inode.link = 1;

    for (int i = 0; i < 16; i++) new_dir_inode.direct_ptr[i] = 0;
    for (int i = 0; i < 8; i++)  new_dir_inode.indirect_ptr[i] = 0;

    new_dir_inode.vstat.st_ino = new_dir_inode.ino;
    new_dir_inode.vstat.st_mode = S_IFDIR | mode;
    new_dir_inode.vstat.st_nlink = 1;
    new_dir_inode.vstat.st_uid = getuid();
    new_dir_inode.vstat.st_gid = getgid();
    new_dir_inode.vstat.st_size = 0;
    new_dir_inode.vstat.st_blksize = BLOCK_SIZE;
    new_dir_inode.vstat.st_blocks = 0;

    time_t now;
    time(&now);
    new_dir_inode.vstat.st_atime = now;
    new_dir_inode.vstat.st_mtime = now;
    new_dir_inode.vstat.st_ctime = now;

    writei(new_dir_inode.ino, &new_dir_inode);

    dir_add(new_dir_inode, new_dir_inode.ino, ".", 1);
    dir_add(new_dir_inode, parent_inode.ino, "..", 2);

    return 0;
}

static int rufs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void)fi;
    struct inode parent_inode, new_file_inode;

    char parent_path[PATH_MAX];
    char name_copy[PATH_MAX];

    strncpy(parent_path, path, PATH_MAX - 1);
    parent_path[PATH_MAX - 1] = '\0';
    strncpy(name_copy, path, PATH_MAX - 1);
    name_copy[PATH_MAX - 1] = '\0';

    char *file_name = basename(name_copy);
    dirname(parent_path);

    if (get_node_by_path(parent_path, 0, &parent_inode) < 0) return -ENOENT;

    int new_ino = get_avail_ino();
    if (new_ino < 0) return -ENOSPC;

    if (dir_add(parent_inode, (uint16_t)new_ino, file_name, strlen(file_name)) < 0)
        return -1;

    memset(&new_file_inode, 0, sizeof(new_file_inode));
    new_file_inode.ino = (uint16_t)new_ino;
    new_file_inode.valid = 1;
    new_file_inode.size = 0;
    new_file_inode.type = S_IFREG;
    new_file_inode.link = 1;

    for (int i = 0; i < 16; i++) new_file_inode.direct_ptr[i] = 0;
    for (int i = 0; i < 8; i++)  new_file_inode.indirect_ptr[i] = 0;

    new_file_inode.vstat.st_ino = new_file_inode.ino;
    new_file_inode.vstat.st_mode = S_IFREG | mode;
    new_file_inode.vstat.st_nlink = 1;
    new_file_inode.vstat.st_uid = getuid();
    new_file_inode.vstat.st_gid = getgid();
    new_file_inode.vstat.st_size = 0;
    new_file_inode.vstat.st_blksize = BLOCK_SIZE;
    new_file_inode.vstat.st_blocks = 0;

    time_t now;
    time(&now);
    new_file_inode.vstat.st_atime = now;
    new_file_inode.vstat.st_mtime = now;
    new_file_inode.vstat.st_ctime = now;

    writei(new_file_inode.ino, &new_file_inode);
    return 0;
}

static int rufs_open(const char *path, struct fuse_file_info *fi) {
    (void)fi;
    struct inode file_inode;
    int ret = get_node_by_path(path, 0, &file_inode);
    if (ret < 0) return ret;
    if (!file_inode.valid) return -ENOENT;
    return 0;
}

static int rufs_read(const char *path, char *buffer, size_t size, off_t offset,
                     struct fuse_file_info *fi) {
    (void)fi;

    struct inode file_inode;
    if (get_node_by_path(path, 0, &file_inode) < 0) return -ENOENT;

    if (offset >= (off_t)file_inode.size) return 0;

    if (offset + (off_t)size > (off_t)file_inode.size)
        size = file_inode.size - offset;

    int block_offset = offset / BLOCK_SIZE;
    int block_start_offset = offset % BLOCK_SIZE;

    int bytes_to_read = (int)size;
    int bytes_read = 0;

    while (bytes_to_read > 0 && block_offset < 16) {
        int blk_index = file_inode.direct_ptr[block_offset];
        if (blk_index == 0) break;

        char data_block[BLOCK_SIZE];
        if (bio_read(g_superblock.d_start_blk + blk_index, data_block) < 0) break;

        int copy_size = BLOCK_SIZE - block_start_offset;
        if (copy_size > bytes_to_read) copy_size = bytes_to_read;

        memcpy(buffer + bytes_read, data_block + block_start_offset, copy_size);

        bytes_read += copy_size;
        bytes_to_read -= copy_size;

        block_offset++;
        block_start_offset = 0;
    }

    return bytes_read;
}

static int rufs_write(const char *path, const char *buffer, size_t size, off_t offset,
                      struct fuse_file_info *fi) {
    (void)fi;

    struct inode file_inode;
    if (get_node_by_path(path, 0, &file_inode) < 0) return -ENOENT;

    int block_offset = offset / BLOCK_SIZE;
    int block_start_offset = offset % BLOCK_SIZE;

    if (block_offset >= 16) return -EFBIG;

    int bytes_to_write = (int)size;
    int bytes_written = 0;

    while (bytes_to_write > 0 && block_offset < 16) {
        char data_block[BLOCK_SIZE];

        if (file_inode.direct_ptr[block_offset] == 0) {
            int new_blk = get_avail_blkno();
            if (new_blk < 0) break;
            file_inode.direct_ptr[block_offset] = new_blk;
            memset(data_block, 0, BLOCK_SIZE);
            file_inode.vstat.st_blocks++;
        } else {
            int blk = g_superblock.d_start_blk + file_inode.direct_ptr[block_offset];
            if (bio_read(blk, data_block) < 0) break;
        }

        int copy_size = BLOCK_SIZE - block_start_offset;
        if (copy_size > bytes_to_write) copy_size = bytes_to_write;

        memcpy(data_block + block_start_offset, buffer + bytes_written, copy_size);

        int blk = g_superblock.d_start_blk + file_inode.direct_ptr[block_offset];
        if (bio_write(blk, data_block) < 0) break;

        bytes_written += copy_size;
        bytes_to_write -= copy_size;

        block_offset++;
        block_start_offset = 0;
    }

    off_t new_size = offset + bytes_written;
    if (new_size > (off_t)file_inode.size) {
        file_inode.size = (uint32_t)new_size;
        file_inode.vstat.st_size = new_size;
    }

    time(&file_inode.vstat.st_mtime);
    writei(file_inode.ino, &file_inode);

    return bytes_written;
}

/* 
 * Functions you DO NOT need to implement for this project
 * (stubs provided for completeness)
 */

static int rufs_rmdir(const char *path) { (void)path; return 0; }
static int rufs_releasedir(const char *path, struct fuse_file_info *fi) { (void)path; (void)fi; return 0; }
static int rufs_unlink(const char *path) { (void)path; return 0; }
static int rufs_truncate(const char *path, off_t size) { (void)path; (void)size; return 0; }
static int rufs_release(const char *path, struct fuse_file_info *fi) { (void)path; (void)fi; return 0; }
static int rufs_flush(const char * path, struct fuse_file_info * fi) { (void)path; (void)fi; return 0; }
static int rufs_utimens(const char *path, const struct timespec tv[2]) { (void)path; (void)tv; return 0; }

static struct fuse_operations rufs_ope = {
    .init       = rufs_init,
    .destroy    = rufs_destroy,

    .getattr    = rufs_getattr,
    .readdir    = rufs_readdir,
    .opendir    = rufs_opendir,
    .mkdir      = rufs_mkdir,

    .create     = rufs_create,
    .open       = rufs_open,
    .read       = rufs_read,
    .write      = rufs_write,

    .rmdir      = rufs_rmdir,
    .releasedir = rufs_releasedir,
    .unlink     = rufs_unlink,
    .truncate   = rufs_truncate,
    .flush      = rufs_flush,
    .utimens    = rufs_utimens,
    .release    = rufs_release
};

int main(int argc, char *argv[]) {
    int fuse_stat;

    getcwd(diskfile_path, PATH_MAX);
    strcat(diskfile_path, "/DISKFILE");

    fuse_stat = fuse_main(argc, argv, &rufs_ope, NULL);
    return fuse_stat;
}