#ifndef SECTOR_CACHE_H
#define SECTOR_CACHE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include "config.h"

/* Cache entry for a single sector */
typedef struct {
    uint64_t sector_idx;           /* Sector index in volume */
    uint8_t *data;                 /* Decrypted sector data (VFS_SECTOR_SIZE) */
    bool dirty;                    /* Sector has been modified */
    bool pinned;                   /* Sector is pinned (never evicted) */
    uint64_t last_access;          /* LRU timestamp */
    bool valid;                    /* Entry contains valid data */
} cache_entry_t;

/* Sector cache context */
typedef struct {
    FILE *file;                    /* Volume file handle */
    uint8_t master_key[KEY_SIZE];         /* Master encryption key */
    uint8_t file_key[KEY_SIZE];     /* File encryption key */
    
    cache_entry_t *entries;         /* Cache entries array */
    size_t cache_size;              /* Number of cache entries */
    size_t max_cache_size;          /* Maximum cache entries (e.g., 4096) */
    
    uint64_t access_counter;        /* Monotonically increasing counter for LRU */
    size_t header_sectors;          /* Number of header sectors (pinned) */
    
    uint64_t total_sectors;         /* Total sectors in volume */
    size_t data_offset;             /* Offset in file where data area begins */
} sector_cache_t;

/* Cache operations */
sector_cache_t* cache_init(FILE *file, const uint8_t *master_key,
                           const uint8_t *file_key, size_t max_entries,
                           size_t data_offset,      /* byte offset where sectors begin */
                           uint64_t total_sectors); /* total encrypted sectors in volume */
void cache_destroy(sector_cache_t *cache);

/*
 * sector_encrypt_write – shared V5 sector encryptor.
 *
 * Encrypts one VFS_SECTOR_SIZE plaintext sector under `file_key` for logical
 * index `idx`, generating a fresh random nonce, and writes the on-disk record
 *   [ciphertext VFS_SECTOR_SIZE][nonce SECTOR_NONCE_SIZE][tag PER_SECTOR_MAC_SIZE]
 * at the file's current position.  The caller is responsible for seeking `f`
 * to the correct offset first.  Used by both volume creation and the cache
 * flush path so the two can never desync.  Returns 0 on success, -1 on error.
 */
int sector_encrypt_write(FILE *f, uint64_t idx,
                         const uint8_t *file_key, const uint8_t *plain);

/* Sector access operations */
int cache_get_sector(sector_cache_t *cache, uint64_t sector_idx, uint8_t **data);
/*
 * cache_get_sector_overwrite – like cache_get_sector but skips loading the
 * sector's previous on-disk contents.  ONLY valid when the caller fills the
 * entire VFS_SECTOR_SIZE buffer before marking it dirty (full-sector
 * overwrite).  Avoids a wasted read + MAC + decrypt on the write path.
 */
int cache_get_sector_overwrite(sector_cache_t *cache, uint64_t sector_idx,
                               uint8_t **data);
/*
 * cache_prefetch_batch – load sectors [start, start+count) into the cache,
 * decrypting/verifying the missing ones in parallel.  `count` is capped
 * internally.  Returns -1 on a hard I/O or authentication failure (the caller
 * must propagate it); 0 otherwise (best-effort — any sectors it could not load
 * are simply fetched serially by the following cache_get_sector calls).
 */
#define SECTOR_PREFETCH_CAP 256
int cache_prefetch_batch(sector_cache_t *cache, uint64_t start, size_t count);
int cache_mark_dirty(sector_cache_t *cache, uint64_t sector_idx);
int cache_pin_sector(sector_cache_t *cache, uint64_t sector_idx);

/* Cache management */
int cache_flush_all(sector_cache_t *cache);
int cache_flush_sector(sector_cache_t *cache, uint64_t sector_idx);

/* Utility functions */
void cache_wipe_sector(uint8_t *data);
size_t cache_get_memory_usage(sector_cache_t *cache);

#endif /* SECTOR_CACHE_H */
