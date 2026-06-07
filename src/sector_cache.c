/*
 * sector_cache.c — sector-level encrypted-I/O cache
 *
 * Bug fixes applied in this rewrite:
 *   Bug 1  – Invalidate cache slot BEFORE loading so a failed load leaves a
 *             consistent (empty) state instead of valid=true / data=NULL.
 *   Bug 2  – decrypt_sector_at() issues its own fseeko() for every attempt,
 *             so the master_key fallback always reads from the right offset.
 *   Bug 3  – total_sectors is now passed in by the caller (volume_open),
 *             not computed from the whole file size (which includes the
 *             crypto header).
 *   Bug 4  – lru_victim() returns SIZE_MAX when every slot is pinned instead
 *             of returning slot 0 (a pinned slot).
 *   Bug 5  – All VFS_SECTOR_SIZE buffers are pre-allocated in cache_init()
 *             so the hot path never calls malloc / free.
 *
 * Portable large-file support: define _FILE_OFFSET_BITS before any system
 * header so that off_t and fseeko() handle offsets > 2 GB on 32-bit targets.
 */
#define _FILE_OFFSET_BITS 64

#include "sector_cache.h"
#include "utils.h"
#include "permut2048.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <sys/mman.h>

#define DEFAULT_CACHE_SIZE  4096
#define PER_SECTOR_MAC_SIZE 32

/* On-disk size of one V5 sector record: ciphertext + nonce + MAC tag. */
#define SECTOR_RECORD_SIZE  (VFS_SECTOR_SIZE + SECTOR_NONCE_SIZE + PER_SECTOR_MAC_SIZE)

/* Keystream domain string, absorbed unconditionally after key || nonce. */
#define K5_SECTOR_DOMAIN    "K5SEC"
#define K5_SECTOR_DOMAIN_LEN 5

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Little-endian 64-bit store (portable) */
static void store_le64(uint8_t p[8], uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

/*
 * derive_sector_key – per-sector key = BLAKE2b(file_key, key=LE64(idx)).
 * Uses an explicit little-endian index so volumes are portable across
 * byte orders.
 */
static void derive_sector_key(const uint8_t *file_key, uint64_t idx,
                              uint8_t out_key[KEY_SIZE]) {
    uint8_t idx_le[8];
    store_le64(idx_le, idx);
    crypto_generichash(out_key, KEY_SIZE, file_key, KEY_SIZE, idx_le, sizeof(idx_le));
}

/*
 * sector_keystream_xor – derive the V5 keystream from sector_key and the
 * stored per-sector nonce, and XOR it across `src` into `dst`.
 *
 *     keystream = Krakken(sector_key || nonce || "K5SEC")
 *
 * Symmetric: used for both encrypt (plain->cipher) and decrypt (cipher->plain).
 */
static void sector_keystream_xor(const uint8_t *sector_key, const uint8_t *nonce,
                                 const uint8_t *src, uint8_t *dst) {
    permut2048_ctx sponge = { .rate = PERMUT2048_RATE };
    permut2048_absorb(&sponge, sector_key, KEY_SIZE);
    permut2048_absorb(&sponge, nonce, SECTOR_NONCE_SIZE);
    permut2048_absorb(&sponge, (const uint8_t *)K5_SECTOR_DOMAIN, K5_SECTOR_DOMAIN_LEN);
    permut2048_finalize(&sponge);

    uint8_t keystream[VFS_SECTOR_SIZE];
    permut2048_squeeze(&sponge, keystream, VFS_SECTOR_SIZE);
    for (size_t i = 0; i < VFS_SECTOR_SIZE; i++)
        dst[i] = src[i] ^ keystream[i];
    secure_zero(keystream, VFS_SECTOR_SIZE);
    secure_zero(&sponge, sizeof(sponge));
}

/*
 * sector_mac – MAC = BLAKE2b(key=sector_key) over LE64(idx) || nonce || cipher.
 * The stored nonce is authenticated so it cannot be swapped to redirect the
 * keystream of an otherwise-valid ciphertext.
 */
static void sector_mac(const uint8_t *sector_key, uint64_t idx,
                       const uint8_t *nonce, const uint8_t *cipher,
                       uint8_t out_tag[PER_SECTOR_MAC_SIZE]) {
    uint8_t idx_le[8];
    store_le64(idx_le, idx);
    crypto_generichash_state mac;
    crypto_generichash_init(&mac, sector_key, KEY_SIZE, PER_SECTOR_MAC_SIZE);
    crypto_generichash_update(&mac, idx_le, sizeof(idx_le));
    crypto_generichash_update(&mac, nonce, SECTOR_NONCE_SIZE);
    crypto_generichash_update(&mac, cipher, VFS_SECTOR_SIZE);
    crypto_generichash_final(&mac, out_tag, PER_SECTOR_MAC_SIZE);
}

/*
 * sector_encrypt_write – shared V5 sector encryptor (see header).  Generates a
 * fresh random nonce on every call, so rewriting a sector never reuses the
 * keystream.  Writes [cipher][nonce][tag] at the file's current position.
 */
int sector_encrypt_write(FILE *f, uint64_t idx,
                         const uint8_t *file_key, const uint8_t *plain) {
    uint8_t sector_key[KEY_SIZE];
    derive_sector_key(file_key, idx, sector_key);

    uint8_t nonce[SECTOR_NONCE_SIZE];
    random_bytes(nonce, SECTOR_NONCE_SIZE);

    uint8_t cipher[VFS_SECTOR_SIZE];
    sector_keystream_xor(sector_key, nonce, plain, cipher);

    uint8_t tag[PER_SECTOR_MAC_SIZE];
    sector_mac(sector_key, idx, nonce, cipher, tag);
    secure_zero(sector_key, KEY_SIZE);

    int ok = (fwrite(cipher, 1, VFS_SECTOR_SIZE, f) == VFS_SECTOR_SIZE)
          && (fwrite(nonce, 1, SECTOR_NONCE_SIZE, f) == SECTOR_NONCE_SIZE)
          && (fwrite(tag, 1, PER_SECTOR_MAC_SIZE, f) == PER_SECTOR_MAC_SIZE);
    return ok ? 0 : -1;
}

/*
 * encrypt_sector_at – seek to the record for `sector_idx` and write it via the
 * shared sector encryptor.
 */
static int encrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                              const uint8_t *plain) {
    const off_t file_off = (off_t)cache->data_offset
                         + (off_t)sector_idx * (off_t)SECTOR_RECORD_SIZE;

    if (fseeko(cache->file, file_off, SEEK_SET) != 0)
        return -1;
    return sector_encrypt_write(cache->file, sector_idx, cache->file_key, plain);
}

/*
 * decrypt_sector_at – read [cipher][nonce][tag] for `sector_idx`, authenticate
 * under the file_key, and decrypt into `out_plain`.  Single format: no key
 * fallback.
 */
static int decrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                              uint8_t *out_plain) {
    const off_t file_off = (off_t)cache->data_offset
                         + (off_t)sector_idx * (off_t)SECTOR_RECORD_SIZE;

    uint8_t sector_key[KEY_SIZE];
    uint8_t cipher[VFS_SECTOR_SIZE];
    uint8_t nonce[SECTOR_NONCE_SIZE];
    uint8_t stored_tag[PER_SECTOR_MAC_SIZE], computed_tag[PER_SECTOR_MAC_SIZE];

    if (fseeko(cache->file, file_off, SEEK_SET) != 0)
        return -1;

    if (fread(cipher, 1, VFS_SECTOR_SIZE, cache->file) != VFS_SECTOR_SIZE ||
        fread(nonce, 1, SECTOR_NONCE_SIZE, cache->file) != SECTOR_NONCE_SIZE ||
        fread(stored_tag, 1, PER_SECTOR_MAC_SIZE, cache->file) != PER_SECTOR_MAC_SIZE)
        return -1;

    derive_sector_key(cache->file_key, sector_idx, sector_key);
    sector_mac(sector_key, sector_idx, nonce, cipher, computed_tag);

    if (ct_memcmp(stored_tag, computed_tag, PER_SECTOR_MAC_SIZE) != 0) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    sector_keystream_xor(sector_key, nonce, cipher, out_plain);
    secure_zero(sector_key, KEY_SIZE);
    return 0;
}

/*
 * lru_victim – return the index of the best slot to evict.
 *
 * Bug 4 fix: returns SIZE_MAX when every slot is pinned so the caller can
 * detect the "no evictable slot" condition without silently overwriting a
 * pinned entry.
 */
static size_t lru_victim(sector_cache_t *cache) {
    size_t   victim        = SIZE_MAX;
    uint64_t oldest_access = UINT64_MAX;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (!cache->entries[i].valid)
            return i;  /* Empty slot is always preferable */
        if (!cache->entries[i].pinned &&
            cache->entries[i].last_access < oldest_access) {
            oldest_access = cache->entries[i].last_access;
            victim = i;
        }
    }
    return victim;  /* SIZE_MAX when every slot is pinned */
}

/* -------------------------------------------------------------------------
 * Public API
 * ---------------------------------------------------------------------- */

/*
 * cache_init – allocate and initialise the sector cache.
 *
 * Bug 3 fix: data_offset and total_sectors are provided by the caller
 * (volume_open), which already knows the precise data region boundaries.
 * We no longer call ftell/fseek internally, so the arithmetic based on
 * the full file size (which includes the crypto header) is avoided.
 *
 * All VFS_SECTOR_SIZE buffers are pre-allocated here via posix_memalign so
 * the hot path (cache_get_sector) never calls malloc or free.
 */
sector_cache_t *cache_init(FILE *file, const uint8_t *master_key,
                            const uint8_t *file_key, size_t max_entries,
                            size_t data_offset, uint64_t total_sectors) {
    if (!file || !master_key || !file_key)
        return NULL;

    sector_cache_t *cache = calloc(1, sizeof(sector_cache_t));
    if (!cache)
        return NULL;
    lock_sensitive(cache, sizeof(sector_cache_t));

    cache->file          = file;
    cache->data_offset   = data_offset;
    cache->total_sectors = total_sectors;
    cache->cache_size    = 0;  /* unused; zeroed for ABI compatibility */
    memcpy(cache->master_key, master_key, KEY_SIZE);
    memcpy(cache->file_key,   file_key,   KEY_SIZE);

    cache->max_cache_size = max_entries ? max_entries : DEFAULT_CACHE_SIZE;
    cache->entries = calloc(cache->max_cache_size, sizeof(cache_entry_t));
    if (!cache->entries) {
        free(cache);
        return NULL;
    }

    /* Pre-allocate every sector buffer so the hot path never calls malloc. */
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (posix_memalign((void **)&cache->entries[i].data,
                           64, VFS_SECTOR_SIZE) != 0) {
            /* Roll back already-allocated buffers. */
            for (size_t j = 0; j < i; j++) {
                secure_zero(cache->entries[j].data, VFS_SECTOR_SIZE);
                free(cache->entries[j].data);
            }
            free(cache->entries);
            free(cache);
            return NULL;
        }
        memset(cache->entries[i].data, 0, VFS_SECTOR_SIZE);
        cache->entries[i].valid      = false;
        cache->entries[i].sector_idx = UINT64_MAX;
        cache->entries[i].dirty      = false;
        cache->entries[i].pinned     = false;
        cache->entries[i].last_access = 0;
    }

    cache->access_counter = 0;
    cache->header_sectors = 0;
    return cache;
}

/*
 * cache_destroy – flush dirty sectors, wipe all buffers and keys, free memory.
 */
void cache_destroy(sector_cache_t *cache) {
    if (!cache)
        return;

    cache_flush_all(cache);

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].data) {
            cache_wipe_sector(cache->entries[i].data);
            munlock(cache->entries[i].data, VFS_SECTOR_SIZE);
            free(cache->entries[i].data);
            cache->entries[i].data = NULL;
        }
    }

    /* Wipe cryptographic keys before releasing the struct. */
    secure_zero(cache->master_key, KEY_SIZE);
    secure_zero(cache->file_key,   KEY_SIZE);

    free(cache->entries);
    free(cache);
}

/*
 * cache_get_sector – return a pointer to the decrypted sector data for
 * `sector_idx`, loading it from disk if not already cached.
 *
 * Bug 1 fix: the evicted slot is marked invalid (valid=false,
 * sector_idx=UINT64_MAX) BEFORE decrypt_sector_at() is called.  If the
 * decrypt fails, the slot is left in a clean, empty state so a subsequent
 * cache-hit scan for the same sector cannot return a NULL data pointer.
 */
int cache_get_sector(sector_cache_t *cache, uint64_t sector_idx, uint8_t **data) {
    if (!cache || !data || sector_idx >= cache->total_sectors)
        return -1;

    /* Fast path: sector already cached. */
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            *data = cache->entries[i].data;
            cache->entries[i].last_access = cache->access_counter++;
            return 0;
        }
    }

    /* Select an eviction candidate. */
    size_t slot = lru_victim(cache);
    if (slot == SIZE_MAX)
        return -1;  /* Every slot is pinned — should not happen in practice. */

    cache_entry_t *e = &cache->entries[slot];

    /* Flush dirty data before evicting the old occupant. */
    if (e->valid && !e->pinned && e->dirty) {
        if (cache_flush_sector(cache, e->sector_idx) != 0)
            return -1;
    }

    /*
     * Wipe the buffer and mark the slot invalid BEFORE the load.
     * Any I/O or authentication failure in decrypt_sector_at() will leave
     * the slot in a clean, reusable state (valid=false, data zeroed).
     * This prevents a subsequent cache-hit from returning a NULL or stale
     * data pointer (Bug 1 fix).
     */
    cache_wipe_sector(e->data);
    e->valid      = false;
    e->sector_idx = UINT64_MAX;
    e->dirty      = false;
    e->pinned     = false;

    /*
     * Load and authenticate the sector.  decrypt_sector_at() issues its own
     * fseeko() for each attempt, so the master_key fallback always reads from
     * the correct file offset (Bug 2 fix).
     */
    if (decrypt_sector_at(cache, sector_idx, e->data) != 0)
        return -1;

    /* Commit the loaded entry. */
    e->sector_idx  = sector_idx;
    e->valid       = true;
    e->dirty       = false;
    e->pinned      = false;
    e->last_access = cache->access_counter++;

    mlock(e->data, VFS_SECTOR_SIZE);  /* best-effort; non-fatal on failure */

    *data = e->data;
    return 0;
}

/* Mark a cached sector as dirty (will be flushed on eviction or explicit flush). */
int cache_mark_dirty(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            cache->entries[i].dirty       = true;
            cache->entries[i].last_access = cache->access_counter++;
            return 0;
        }
    }
    return -1;  /* Sector not found in cache */
}

/* Pin a sector so it is never evicted. */
int cache_pin_sector(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    /* Ensure the sector is in the cache first. */
    uint8_t *data_ptr;
    if (cache_get_sector(cache, sector_idx, &data_ptr) != 0)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            cache->entries[i].pinned = true;
            cache->header_sectors++;
            return 0;
        }
    }
    return -1;
}

/*
 * cache_flush_sector – write a dirty sector back to the encrypted volume.
 * encrypt_sector_at() performs its own fseeko().
 */
int cache_flush_sector(sector_cache_t *cache, uint64_t sector_idx) {
    if (!cache || sector_idx >= cache->total_sectors)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx &&
            cache->entries[i].dirty) {

            if (encrypt_sector_at(cache, sector_idx,
                                  cache->entries[i].data) != 0)
                return -1;

            cache->entries[i].dirty = false;
            return 0;
        }
    }
    return 0;  /* Sector not dirty or not found — nothing to do. */
}

/* Flush every dirty sector to disk. */
int cache_flush_all(sector_cache_t *cache) {
    if (!cache)
        return -1;

    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid && cache->entries[i].dirty) {
            if (cache_flush_sector(cache, cache->entries[i].sector_idx) != 0)
                return -1;
        }
    }
    fflush(cache->file);
    return 0;
}

/* Securely zero a sector-sized buffer. */
void cache_wipe_sector(uint8_t *data) {
    if (data)
        secure_zero(data, VFS_SECTOR_SIZE);
}

/* Report total memory consumed by the cache (all buffers pre-allocated). */
size_t cache_get_memory_usage(sector_cache_t *cache) {
    if (!cache)
        return 0;

    return sizeof(sector_cache_t)
         + cache->max_cache_size * sizeof(cache_entry_t)
         + cache->max_cache_size * VFS_SECTOR_SIZE;  /* all pre-allocated */
}
