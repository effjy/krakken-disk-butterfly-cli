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
#include <pthread.h>
#include <unistd.h>

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
 * sector_build_record – produce one on-disk V5 record for sector `idx` into
 * `rec` (laid out [cipher][nonce][tag], SECTOR_RECORD_SIZE bytes).  Generates a
 * fresh random nonce.  Pure with respect to shared state: it touches only the
 * read-only `file_key`, the caller-owned `plain` input and `rec` output, so
 * many records may be built concurrently from worker threads.  This is the
 * single source of the on-disk format, shared by the serial write path and the
 * parallel flush path so the two can never desync.
 */
static int encrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                             const uint8_t *plain);

static void sector_build_record(uint64_t idx, const uint8_t *file_key,
                                const uint8_t *plain, uint8_t *rec) {
    uint8_t *cipher = rec;
    uint8_t *nonce  = rec + VFS_SECTOR_SIZE;
    uint8_t *tag    = rec + VFS_SECTOR_SIZE + SECTOR_NONCE_SIZE;

    uint8_t sector_key[KEY_SIZE];
    derive_sector_key(file_key, idx, sector_key);

    random_bytes(nonce, SECTOR_NONCE_SIZE);
    sector_keystream_xor(sector_key, nonce, plain, cipher);
    sector_mac(sector_key, idx, nonce, cipher, tag);

    secure_zero(sector_key, KEY_SIZE);
}

/*
 * sector_encrypt_write – shared V5 sector encryptor (see header).  Generates a
 * fresh random nonce on every call, so rewriting a sector never reuses the
 * keystream.  Writes [cipher][nonce][tag] at the file's current position.
 */
int sector_encrypt_write(FILE *f, uint64_t idx,
                         const uint8_t *file_key, const uint8_t *plain) {
    uint8_t rec[SECTOR_RECORD_SIZE];
    sector_build_record(idx, file_key, plain, rec);
    int ok = (fwrite(rec, 1, SECTOR_RECORD_SIZE, f) == SECTOR_RECORD_SIZE);
    secure_zero(rec, SECTOR_RECORD_SIZE);
    return ok ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * Parallel dirty-sector flush
 *
 * Sector records are mutually independent (each has its own derived key, random
 * nonce, keystream and MAC), so the CPU-heavy part — building the records — is
 * embarrassingly parallel.  We split the dirty set across a handful of worker
 * threads to build every record, then write them back sequentially on the
 * calling thread (file I/O stays single-threaded, preserving the on-disk
 * layout exactly).  Threads are spawned per flush *batch*, not per sector, so
 * pthread_create cost is amortised across the whole dirty set.
 * ---------------------------------------------------------------------- */

#define SECTOR_FLUSH_MAX_THREADS 8

/* Optional instrumentation: set KRAKKEN_SC_STATS=1 to print, at cache_destroy,
 * how many sectors were decrypted/encrypted on the parallel batch paths. */
static unsigned long g_sc_parallel_loaded  = 0;
static unsigned long g_sc_parallel_flushed = 0;

static int sc_n_threads(void) {
    const char *e = getenv("KRAKKEN_THREADS");
    if (e && *e) {
        int v = atoi(e);
        if (v >= 1 && v <= SECTOR_FLUSH_MAX_THREADS) return v;
    }
    long n = sysconf(_SC_NPROCESSORS_ONLN);
    if (n <= 0) return 4;
    if (n > SECTOR_FLUSH_MAX_THREADS) return SECTOR_FLUSH_MAX_THREADS;
    return (int)n;
}

typedef struct {
    sector_cache_t *cache;
    const size_t   *slots;    /* entry indices of the dirty sectors */
    uint8_t        *records;  /* contiguous SECTOR_RECORD_SIZE blocks */
    size_t          start;
    size_t          end;
} flush_worker_t;

static void *flush_worker(void *arg) {
    flush_worker_t *w = arg;
    for (size_t i = w->start; i < w->end; i++) {
        const cache_entry_t *e = &w->cache->entries[w->slots[i]];
        sector_build_record(e->sector_idx, w->cache->file_key, e->data,
                            w->records + i * SECTOR_RECORD_SIZE);
    }
    return NULL;
}

/* Serial fallback used when allocation fails: build + write one at a time. */
static int flush_dirty_serial(sector_cache_t *cache) {
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        cache_entry_t *e = &cache->entries[i];
        if (e->valid && e->dirty) {
            if (encrypt_sector_at(cache, e->sector_idx, e->data) != 0)
                return -1;
            e->dirty = false;
        }
    }
    return 0;
}

/*
 * flush_dirty_batch_parallel – flush every currently-dirty sector.  Records are
 * built in parallel, then written back sequentially in ascending entry order.
 * Each flushed entry is marked clean (it stays cached/valid).  Safe to flush
 * more than strictly required: it only ever writes back accurate data.
 */
static int flush_dirty_batch_parallel(sector_cache_t *cache) {
    size_t n = 0;
    for (size_t i = 0; i < cache->max_cache_size; i++)
        if (cache->entries[i].valid && cache->entries[i].dirty) n++;
    if (n == 0) return 0;

    size_t  *slots   = malloc(n * sizeof(size_t));
    uint8_t *records = malloc(n * SECTOR_RECORD_SIZE);
    if (!slots || !records) {
        free(slots);
        free(records);
        return flush_dirty_serial(cache);  /* low-memory fallback */
    }

    size_t k = 0;
    for (size_t i = 0; i < cache->max_cache_size; i++)
        if (cache->entries[i].valid && cache->entries[i].dirty) slots[k++] = i;

    int nt = sc_n_threads();
    if ((size_t)nt > n) nt = (int)n;

    pthread_t      tids[SECTOR_FLUSH_MAX_THREADS];
    flush_worker_t workers[SECTOR_FLUSH_MAX_THREADS];
    size_t base = n / (size_t)nt, extra = n % (size_t)nt, cur = 0;
    for (int t = 0; t < nt; t++) {
        workers[t].cache   = cache;
        workers[t].slots   = slots;
        workers[t].records = records;
        workers[t].start   = cur;
        workers[t].end     = cur + base + ((size_t)t < extra ? 1 : 0);
        cur = workers[t].end;
    }

    /* Spawn workers; on any failure run the rest inline on this thread. */
    int spawned = 0;
    for (int t = 0; t < nt; t++) {
        if (pthread_create(&tids[t], NULL, flush_worker, &workers[t]) != 0) {
            for (int j = t; j < nt; j++) flush_worker(&workers[j]);
            break;
        }
        spawned++;
    }
    for (int t = 0; t < spawned; t++) pthread_join(tids[t], NULL);

    /* Sequential write-back in ascending entry order. */
    int ret = 0;
    for (size_t i = 0; i < n; i++) {
        cache_entry_t *e = &cache->entries[slots[i]];
        const off_t off = (off_t)cache->data_offset
                        + (off_t)e->sector_idx * (off_t)SECTOR_RECORD_SIZE;
        if (fseeko(cache->file, off, SEEK_SET) != 0 ||
            fwrite(records + i * SECTOR_RECORD_SIZE, 1, SECTOR_RECORD_SIZE,
                   cache->file) != SECTOR_RECORD_SIZE) {
            ret = -1;
            break;
        }
        e->dirty = false;
    }
    g_sc_parallel_flushed += n;

    secure_zero(records, n * SECTOR_RECORD_SIZE);
    free(records);
    free(slots);
    return ret;
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
/*
 * sector_open_record – authenticate one on-disk record `rec`
 * ([cipher][nonce][tag], SECTOR_RECORD_SIZE bytes) for sector `idx` under
 * `file_key` and decrypt into `out_plain`.  Pure w.r.t. shared state (reads
 * only file_key + rec, writes only out_plain), so many records may be opened
 * concurrently.  This is the read-side twin of sector_build_record: one shared
 * definition of the format for the serial and parallel paths.  Returns 0 on
 * success, -1 on authentication failure.
 */
static int sector_open_record(uint64_t idx, const uint8_t *file_key,
                              const uint8_t *rec, uint8_t *out_plain) {
    const uint8_t *cipher = rec;
    const uint8_t *nonce  = rec + VFS_SECTOR_SIZE;
    const uint8_t *tag    = rec + VFS_SECTOR_SIZE + SECTOR_NONCE_SIZE;

    uint8_t sector_key[KEY_SIZE];
    derive_sector_key(file_key, idx, sector_key);

    uint8_t computed_tag[PER_SECTOR_MAC_SIZE];
    sector_mac(sector_key, idx, nonce, cipher, computed_tag);
    if (ct_memcmp(tag, computed_tag, PER_SECTOR_MAC_SIZE) != 0) {
        secure_zero(sector_key, KEY_SIZE);
        return -1;
    }

    sector_keystream_xor(sector_key, nonce, cipher, out_plain);
    secure_zero(sector_key, KEY_SIZE);
    return 0;
}

static int decrypt_sector_at(sector_cache_t *cache, uint64_t sector_idx,
                              uint8_t *out_plain) {
    const off_t file_off = (off_t)cache->data_offset
                         + (off_t)sector_idx * (off_t)SECTOR_RECORD_SIZE;

    if (fseeko(cache->file, file_off, SEEK_SET) != 0)
        return -1;

    uint8_t rec[SECTOR_RECORD_SIZE];
    if (fread(rec, 1, SECTOR_RECORD_SIZE, cache->file) != SECTOR_RECORD_SIZE)
        return -1;

    int r = sector_open_record(sector_idx, cache->file_key, rec, out_plain);
    secure_zero(rec, SECTOR_RECORD_SIZE);
    return r;
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

    if (getenv("KRAKKEN_SC_STATS")) {
        fprintf(stderr,
                "[sector_cache] parallel sectors: %lu decrypted (read), "
                "%lu encrypted (flush)\n",
                g_sc_parallel_loaded, g_sc_parallel_flushed);
    }
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

    /*
     * Flush dirty data before evicting the old occupant.  Rather than write
     * back just this one victim serially, flush the whole dirty set in
     * parallel: the victim becomes clean (and reusable), and the many other
     * dirty sectors a large copy accumulates are cleaned in one parallel batch,
     * so subsequent evictions find clean slots and skip I/O entirely.
     */
    if (e->valid && !e->pinned && e->dirty) {
        if (flush_dirty_batch_parallel(cache) != 0)
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

/*
 * cache_get_sector_overwrite – obtain a writable buffer for `sector_idx`
 * WITHOUT loading/decrypting its previous on-disk contents.  Intended for the
 * case where the caller will overwrite the ENTIRE sector (e.g. a full-sector
 * file copy), so the read + MAC-verify + keystream-decrypt of the old contents
 * would be pure waste.  Skipping it removes the serial decrypt that otherwise
 * dominates the write path, leaving the parallel flush as the real cost.
 *
 * Contract: the caller MUST fill all VFS_SECTOR_SIZE bytes of *data and then
 * call cache_mark_dirty(); the returned buffer may hold stale plaintext from a
 * previous occupant until overwritten.
 */
int cache_get_sector_overwrite(sector_cache_t *cache, uint64_t sector_idx,
                               uint8_t **data) {
    if (!cache || !data || sector_idx >= cache->total_sectors)
        return -1;

    /* Already cached: reuse the slot (its contents will be fully overwritten). */
    for (size_t i = 0; i < cache->max_cache_size; i++) {
        if (cache->entries[i].valid &&
            cache->entries[i].sector_idx == sector_idx) {
            *data = cache->entries[i].data;
            cache->entries[i].last_access = cache->access_counter++;
            return 0;
        }
    }

    size_t slot = lru_victim(cache);
    if (slot == SIZE_MAX)
        return -1;

    cache_entry_t *e = &cache->entries[slot];

    /* Same parallel write-back as the normal eviction path. */
    if (e->valid && !e->pinned && e->dirty) {
        if (flush_dirty_batch_parallel(cache) != 0)
            return -1;
    }

    /* Claim the slot for the new sector — no decrypt_sector_at() load. */
    e->sector_idx  = sector_idx;
    e->valid       = true;
    e->dirty       = false;
    e->pinned      = false;
    e->last_access = cache->access_counter++;

    mlock(e->data, VFS_SECTOR_SIZE);  /* best-effort; non-fatal on failure */

    *data = e->data;
    return 0;
}

/* -------------------------------------------------------------------------
 * Parallel batch prefetch (read path)
 *
 * Loads a run of sectors into the cache: the records are read from disk
 * sequentially on this thread (the FILE* offset is single-threaded), then the
 * CPU-heavy MAC-verify + keystream-decrypt is fanned out across worker threads.
 * After a successful prefetch, the normal per-sector cache_get_sector() calls
 * in vfs_read_data become pure cache hits with no decrypt.
 *
 * Sectors already resident in the cache (possibly dirty) are left untouched, so
 * unflushed modifications are never shadowed by stale on-disk data.
 * ---------------------------------------------------------------------- */

typedef struct {
    sector_cache_t *cache;
    const size_t   *slots;    /* cache slot for each job */
    const uint64_t *idxs;     /* sector index for each job */
    const uint8_t  *records;  /* contiguous SECTOR_RECORD_SIZE blocks */
    int            *fail;     /* per-job failure flags */
    size_t          start;
    size_t          end;
} load_worker_t;

static void *load_worker(void *arg) {
    load_worker_t *w = arg;
    for (size_t j = w->start; j < w->end; j++) {
        uint8_t *dst = w->cache->entries[w->slots[j]].data;
        if (sector_open_record(w->idxs[j], w->cache->file_key,
                               w->records + j * SECTOR_RECORD_SIZE, dst) != 0)
            w->fail[j] = 1;
    }
    return NULL;
}

/*
 * cache_prefetch_batch – ensure sectors [start, start+count) are resident,
 * loading the missing ones in parallel.  `count` is capped internally.
 * Returns 0 on success (best-effort: on allocation failure it simply returns 0
 * and lets the caller fall back to per-sector loads); -1 only on a hard I/O or
 * authentication failure, which the caller must propagate.
 */
int cache_prefetch_batch(sector_cache_t *cache, uint64_t start, size_t count) {
    if (!cache) return -1;
    if (count > SECTOR_PREFETCH_CAP) count = SECTOR_PREFETCH_CAP;
    if (count == 0) return 0;

    size_t   *slots   = malloc(count * sizeof(size_t));
    uint64_t *idxs    = malloc(count * sizeof(uint64_t));
    uint8_t  *records = malloc(count * SECTOR_RECORD_SIZE);
    int      *fail    = calloc(count, sizeof(int));
    if (!slots || !idxs || !records || !fail) {
        free(slots); free(idxs); free(records); free(fail);
        return 0;  /* non-fatal: caller falls back to serial cache_get_sector */
    }

    int ret = 0;
    size_t njobs = 0;
    for (size_t s = 0; s < count; s++) {
        uint64_t idx = start + s;
        if (idx >= cache->total_sectors) break;

        /* Already cached? Touch LRU and skip — never shadow a dirty sector. */
        int hit = 0;
        for (size_t i = 0; i < cache->max_cache_size; i++) {
            if (cache->entries[i].valid && cache->entries[i].sector_idx == idx) {
                cache->entries[i].last_access = cache->access_counter++;
                hit = 1;
                break;
            }
        }
        if (hit) continue;

        size_t slot = lru_victim(cache);
        if (slot == SIZE_MAX) break;  /* all pinned: leave the rest to caller */

        cache_entry_t *e = &cache->entries[slot];
        if (e->valid && !e->pinned && e->dirty) {
            if (flush_dirty_batch_parallel(cache) != 0) { ret = -1; goto done; }
        }

        /* Sequential record read into the staging buffer. */
        const off_t off = (off_t)cache->data_offset
                        + (off_t)idx * (off_t)SECTOR_RECORD_SIZE;
        if (fseeko(cache->file, off, SEEK_SET) != 0 ||
            fread(records + njobs * SECTOR_RECORD_SIZE, 1, SECTOR_RECORD_SIZE,
                  cache->file) != SECTOR_RECORD_SIZE) {
            ret = -1;
            goto done;
        }

        /* Claim the slot (decrypt fills e->data in the worker below). */
        cache_wipe_sector(e->data);
        e->sector_idx  = idx;
        e->valid       = true;
        e->dirty       = false;
        e->pinned      = false;
        e->last_access = cache->access_counter++;
        mlock(e->data, VFS_SECTOR_SIZE);

        slots[njobs] = slot;
        idxs[njobs]  = idx;
        njobs++;
    }

    if (njobs == 0) goto done;

    int nt = sc_n_threads();
    if ((size_t)nt > njobs) nt = (int)njobs;

    pthread_t     tids[SECTOR_FLUSH_MAX_THREADS];
    load_worker_t wk[SECTOR_FLUSH_MAX_THREADS];
    size_t base = njobs / (size_t)nt, extra = njobs % (size_t)nt, cur = 0;
    for (int t = 0; t < nt; t++) {
        wk[t].cache = cache; wk[t].slots = slots; wk[t].idxs = idxs;
        wk[t].records = records; wk[t].fail = fail;
        wk[t].start = cur;
        wk[t].end   = cur + base + ((size_t)t < extra ? 1 : 0);
        cur = wk[t].end;
    }
    int spawned = 0;
    for (int t = 0; t < nt; t++) {
        if (pthread_create(&tids[t], NULL, load_worker, &wk[t]) != 0) {
            for (int j = t; j < nt; j++) load_worker(&wk[j]);
            break;
        }
        spawned++;
    }
    for (int t = 0; t < spawned; t++) pthread_join(tids[t], NULL);

    /* Any authentication failure invalidates that slot and fails the batch. */
    for (size_t j = 0; j < njobs; j++) {
        if (fail[j]) {
            cache_entry_t *e = &cache->entries[slots[j]];
            cache_wipe_sector(e->data);
            e->valid = false;
            e->sector_idx = UINT64_MAX;
            ret = -1;
        }
    }
    g_sc_parallel_loaded += njobs;

done:
    secure_zero(records, count * SECTOR_RECORD_SIZE);
    free(slots); free(idxs); free(records); free(fail);
    return ret;
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

/* Flush every dirty sector to disk (records built in parallel). */
int cache_flush_all(sector_cache_t *cache) {
    if (!cache)
        return -1;

    if (flush_dirty_batch_parallel(cache) != 0)
        return -1;

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
