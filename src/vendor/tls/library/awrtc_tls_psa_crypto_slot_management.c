/*
 *  PSA crypto layer on top of Mbed TLS crypto
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_C)

#include "../include/psa/crypto.h"

#include "psa_crypto_core.h"
#include "psa_crypto_driver_wrappers_no_static.h"
#include "psa_crypto_slot_management.h"
#include "psa_crypto_storage.h"
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)
#include "psa_crypto_se.h"
#endif

#include <stdlib.h>
#include <string.h>
#include "../include/mbedtls/platform.h"
#if defined(AWRTC_MBEDTLS_THREADING_C)
#include "../include/mbedtls/threading.h"
#endif



/* Make sure we have distinct ranges of key identifiers for distinct
 * purposes. */
AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_USER_MIN < AWRTC_PSA_KEY_ID_USER_MAX,
                      "Empty user key ID range");
AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_VENDOR_MIN < AWRTC_PSA_KEY_ID_VENDOR_MAX,
                      "Empty vendor key ID range");
AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MIN <= AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MAX,
                      "Empty builtin key ID range");
AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_VOLATILE_MIN <= AWRTC_PSA_KEY_ID_VOLATILE_MAX,
                      "Empty volatile key ID range");

AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_USER_MAX < AWRTC_PSA_KEY_ID_VENDOR_MIN ||
                      AWRTC_PSA_KEY_ID_VENDOR_MAX < AWRTC_PSA_KEY_ID_USER_MIN,
                      "Overlap between user key IDs and vendor key IDs");

AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_VENDOR_MIN <= AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MIN &&
                      AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MAX <= AWRTC_PSA_KEY_ID_VENDOR_MAX,
                      "Builtin key identifiers are not in the vendor range");

AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_VENDOR_MIN <= AWRTC_PSA_KEY_ID_VOLATILE_MIN &&
                      AWRTC_PSA_KEY_ID_VOLATILE_MAX <= AWRTC_PSA_KEY_ID_VENDOR_MAX,
                      "Volatile key identifiers are not in the vendor range");

AWRTC_MBEDTLS_STATIC_ASSERT(AWRTC_PSA_KEY_ID_VOLATILE_MAX < AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MIN ||
                      AWRTC_MBEDTLS_PSA_KEY_ID_BUILTIN_MAX < AWRTC_PSA_KEY_ID_VOLATILE_MIN,
                      "Overlap between builtin key IDs and volatile key IDs");



#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)

/* Dynamic key store.
 *
 * The key store consists of multiple slices.
 *
 * The volatile keys are stored in variable-sized tables called slices.
 * Slices are allocated on demand and deallocated when possible.
 * The size of slices increases exponentially, so the average overhead
 * (number of slots that are allocated but not used) is roughly
 * proportional to the number of keys (with a factor that grows
 * when the key store is fragmented).
 *
 * One slice is dedicated to the cache of persistent and built-in keys.
 * For simplicity, they are separated from volatile keys. This cache
 * slice has a fixed size and has the slice index KEY_SLOT_CACHE_SLICE_INDEX,
 * located after the slices for volatile keys.
 */

/* Size of the last slice containing the cache of persistent and built-in keys. */
#define PERSISTENT_KEY_CACHE_COUNT AWRTC_MBEDTLS_PSA_KEY_SLOT_COUNT

/* Volatile keys are stored in slices 0 through
 * (KEY_SLOT_VOLATILE_SLICE_COUNT - 1) inclusive.
 * Each slice is twice the size of the previous slice.
 * Volatile key identifiers encode the slice number as follows:
 *     bits 30..31:  0b10 (mandated by the PSA Crypto specification).
 *     bits 25..29:  slice index (0...KEY_SLOT_VOLATILE_SLICE_COUNT-1)
 *     bits 0..24:   slot index in slice
 */
#define KEY_ID_SLOT_INDEX_WIDTH 25u
#define KEY_ID_SLICE_INDEX_WIDTH 5u

#define KEY_SLOT_VOLATILE_SLICE_BASE_LENGTH 16u
#define KEY_SLOT_VOLATILE_SLICE_COUNT 22u
#define KEY_SLICE_COUNT (KEY_SLOT_VOLATILE_SLICE_COUNT + 1u)
#define KEY_SLOT_CACHE_SLICE_INDEX KEY_SLOT_VOLATILE_SLICE_COUNT


/* Check that the length of the largest slice (calculated as
 * KEY_SLICE_LENGTH_MAX below) does not overflow size_t. We use
 * an indirect method in case the calculation of KEY_SLICE_LENGTH_MAX
 * itself overflows uintmax_t: if (BASE_LENGTH << c)
 * overflows size_t then BASE_LENGTH > SIZE_MAX >> c.
 */
#if (KEY_SLOT_VOLATILE_SLICE_BASE_LENGTH >              \
     SIZE_MAX >> (KEY_SLOT_VOLATILE_SLICE_COUNT - 1))
#error "Maximum slice length overflows size_t"
#endif

#if KEY_ID_SLICE_INDEX_WIDTH + KEY_ID_SLOT_INDEX_WIDTH > 30
#error "Not enough room in volatile key IDs for slice index and slot index"
#endif
#if KEY_SLOT_VOLATILE_SLICE_COUNT > (1 << KEY_ID_SLICE_INDEX_WIDTH)
#error "Too many slices to fit the slice index in a volatile key ID"
#endif
#define KEY_SLICE_LENGTH_MAX                                            \
    (KEY_SLOT_VOLATILE_SLICE_BASE_LENGTH << (KEY_SLOT_VOLATILE_SLICE_COUNT - 1))
#if KEY_SLICE_LENGTH_MAX > 1 << KEY_ID_SLOT_INDEX_WIDTH
#error "Not enough room in volatile key IDs for a slot index in the largest slice"
#endif
#if KEY_ID_SLICE_INDEX_WIDTH > 8
#error "Slice index does not fit in uint8_t for awrtc_psa_key_slot_t::slice_index"
#endif


/* Calculate the volatile key id to use for a given slot.
 * This function assumes valid parameter values. */
static awrtc_psa_key_id_t volatile_key_id_of_index(size_t slice_idx,
                                             size_t slot_idx)
{
    /* We assert above that the slice and slot indexes fit in separate
     * bit-fields inside awrtc_psa_key_id_t, which is a 32-bit type per the
     * PSA Cryptography specification. */
    return (awrtc_psa_key_id_t) (0x40000000u |
                           (slice_idx << KEY_ID_SLOT_INDEX_WIDTH) |
                           slot_idx);
}

/* Calculate the slice containing the given volatile key.
 * This function assumes valid parameter values. */
static size_t slice_index_of_volatile_key_id(awrtc_psa_key_id_t key_id)
{
    size_t mask = (1LU << KEY_ID_SLICE_INDEX_WIDTH) - 1;
    return (key_id >> KEY_ID_SLOT_INDEX_WIDTH) & mask;
}

/* Calculate the index of the slot containing the given volatile key.
 * This function assumes valid parameter values. */
static size_t slot_index_of_volatile_key_id(awrtc_psa_key_id_t key_id)
{
    return key_id & ((1LU << KEY_ID_SLOT_INDEX_WIDTH) - 1);
}

/* In global_data.first_free_slot_index, use this special value to
 * indicate that the slice is full. */
#define FREE_SLOT_INDEX_NONE ((size_t) -1)

#if defined(AWRTC_MBEDTLS_TEST_HOOKS)
size_t awrtc_psa_key_slot_volatile_slice_count(void)
{
    return KEY_SLOT_VOLATILE_SLICE_COUNT;
}
#endif

#else /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

/* Static key store.
 *
 * All the keys (volatile or persistent) are in a single slice.
 * We only use slices as a concept to allow some differences between
 * static and dynamic key store management to be buried in auxiliary
 * functions.
 */

#define PERSISTENT_KEY_CACHE_COUNT AWRTC_MBEDTLS_PSA_KEY_SLOT_COUNT
#define KEY_SLICE_COUNT 1u
#define KEY_SLOT_CACHE_SLICE_INDEX 0

#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */


typedef struct {
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    awrtc_psa_key_slot_t *key_slices[KEY_SLICE_COUNT];
    size_t first_free_slot_index[KEY_SLOT_VOLATILE_SLICE_COUNT];
#else /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
    awrtc_psa_key_slot_t key_slots[AWRTC_MBEDTLS_PSA_KEY_SLOT_COUNT];
#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
    uint8_t key_slots_initialized;
} awrtc_psa_global_data_t;

static awrtc_psa_global_data_t global_data;

static uint8_t awrtc_psa_get_key_slots_initialized(void)
{
    uint8_t initialized;

#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_lock(&awrtc_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(AWRTC_MBEDTLS_THREADING_C) */

    initialized = global_data.key_slots_initialized;

#if defined(AWRTC_MBEDTLS_THREADING_C)
    awrtc_mbedtls_mutex_unlock(&awrtc_mbedtls_threading_psa_globaldata_mutex);
#endif /* defined(AWRTC_MBEDTLS_THREADING_C) */

    return initialized;
}



/** The length of the given slice in the key slot table.
 *
 * \param slice_idx     The slice number. It must satisfy
 *                      0 <= slice_idx < KEY_SLICE_COUNT.
 *
 * \return              The number of elements in the given slice.
 */
static inline size_t key_slice_length(size_t slice_idx);

/** Get a pointer to the slot where the given volatile key is located.
 *
 * \param key_id        The key identifier. It must be a valid volatile key
 *                      identifier.
 * \return              A pointer to the only slot that the given key
 *                      can be in. Note that the slot may be empty or
 *                      contain a different key.
 */
static inline awrtc_psa_key_slot_t *get_volatile_key_slot(awrtc_psa_key_id_t key_id);

/** Get a pointer to an entry in the persistent key cache.
 *
 * \param slot_idx      The index in the table. It must satisfy
 *                      0 <= slot_idx < PERSISTENT_KEY_CACHE_COUNT.
 * \return              A pointer to the slot containing the given
 *                      persistent key cache entry.
 */
static inline awrtc_psa_key_slot_t *get_persistent_key_slot(size_t slot_idx);

/** Get a pointer to a slot given by slice and index.
 *
 * \param slice_idx     The slice number. It must satisfy
 *                      0 <= slice_idx < KEY_SLICE_COUNT.
 * \param slot_idx      An index in the given slice. It must satisfy
 *                      0 <= slot_idx < key_slice_length(slice_idx).
 *
 * \return              A pointer to the given slot.
 */
static inline awrtc_psa_key_slot_t *get_key_slot(size_t slice_idx, size_t slot_idx);

#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)

#if defined(AWRTC_MBEDTLS_TEST_HOOKS)
size_t (*awrtc_mbedtls_test_hook_psa_volatile_key_slice_length)(size_t slice_idx) = NULL;
#endif

static inline size_t key_slice_length(size_t slice_idx)
{
    if (slice_idx == KEY_SLOT_CACHE_SLICE_INDEX) {
        return PERSISTENT_KEY_CACHE_COUNT;
    } else {
#if defined(AWRTC_MBEDTLS_TEST_HOOKS)
        if (awrtc_mbedtls_test_hook_psa_volatile_key_slice_length != NULL) {
            return awrtc_mbedtls_test_hook_psa_volatile_key_slice_length(slice_idx);
        }
#endif
        return KEY_SLOT_VOLATILE_SLICE_BASE_LENGTH << slice_idx;
    }
}

static inline awrtc_psa_key_slot_t *get_volatile_key_slot(awrtc_psa_key_id_t key_id)
{
    size_t slice_idx = slice_index_of_volatile_key_id(key_id);
    if (slice_idx >= KEY_SLOT_VOLATILE_SLICE_COUNT) {
        return NULL;
    }
    size_t slot_idx = slot_index_of_volatile_key_id(key_id);
    if (slot_idx >= key_slice_length(slice_idx)) {
        return NULL;
    }
    awrtc_psa_key_slot_t *slice = global_data.key_slices[slice_idx];
    if (slice == NULL) {
        return NULL;
    }
    return &slice[slot_idx];
}

static inline awrtc_psa_key_slot_t *get_persistent_key_slot(size_t slot_idx)
{
    return &global_data.key_slices[KEY_SLOT_CACHE_SLICE_INDEX][slot_idx];
}

static inline awrtc_psa_key_slot_t *get_key_slot(size_t slice_idx, size_t slot_idx)
{
    return &global_data.key_slices[slice_idx][slot_idx];
}

#else /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

static inline size_t key_slice_length(size_t slice_idx)
{
    (void) slice_idx;
    return ARRAY_LENGTH(global_data.key_slots);
}

static inline awrtc_psa_key_slot_t *get_volatile_key_slot(awrtc_psa_key_id_t key_id)
{
    AWRTC_MBEDTLS_STATIC_ASSERT(ARRAY_LENGTH(global_data.key_slots) <=
                          AWRTC_PSA_KEY_ID_VOLATILE_MAX - AWRTC_PSA_KEY_ID_VOLATILE_MIN + 1,
                          "The key slot array is larger than the volatile key ID range");
    return &global_data.key_slots[key_id - AWRTC_PSA_KEY_ID_VOLATILE_MIN];
}

static inline awrtc_psa_key_slot_t *get_persistent_key_slot(size_t slot_idx)
{
    return &global_data.key_slots[slot_idx];
}

static inline awrtc_psa_key_slot_t *get_key_slot(size_t slice_idx, size_t slot_idx)
{
    (void) slice_idx;
    return &global_data.key_slots[slot_idx];
}

#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */



int awrtc_psa_is_valid_key_id(awrtc_mbedtls_svc_key_id_t key, int vendor_ok)
{
    awrtc_psa_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key);

    if ((AWRTC_PSA_KEY_ID_USER_MIN <= key_id) &&
        (key_id <= AWRTC_PSA_KEY_ID_USER_MAX)) {
        return 1;
    }

    if (vendor_ok &&
        (AWRTC_PSA_KEY_ID_VENDOR_MIN <= key_id) &&
        (key_id <= AWRTC_PSA_KEY_ID_VENDOR_MAX)) {
        return 1;
    }

    return 0;
}

/** Get the description in memory of a key given its identifier and lock it.
 *
 * The descriptions of volatile keys and loaded persistent keys are
 * stored in key slots. This function returns a pointer to the key slot
 * containing the description of a key given its identifier.
 *
 * The function searches the key slots containing the description of the key
 * with \p key identifier. The function does only read accesses to the key
 * slots. The function does not load any persistent key thus does not access
 * any storage.
 *
 * For volatile key identifiers, only one key slot is queried as a volatile
 * key with identifier key_id can only be stored in slot of index
 * ( key_id - #AWRTC_PSA_KEY_ID_VOLATILE_MIN ).
 *
 * On success, the function locks the key slot. It is the responsibility of
 * the caller to unlock the key slot when it does not access it anymore.
 *
 * If multi-threading is enabled, the caller must hold the
 * global key slot mutex.
 *
 * \param key           Key identifier to query.
 * \param[out] p_slot   On success, `*p_slot` contains a pointer to the
 *                      key slot containing the description of the key
 *                      identified by \p key.
 *
 * \retval #AWRTC_PSA_SUCCESS
 *         The pointer to the key slot containing the description of the key
 *         identified by \p key was returned.
 * \retval #AWRTC_PSA_ERROR_INVALID_HANDLE
 *         \p key is not a valid key identifier.
 * \retval #AWRTC_PSA_ERROR_DOES_NOT_EXIST
 *         There is no key with key identifier \p key in the key slots.
 */
static awrtc_psa_status_t awrtc_psa_get_and_lock_key_slot_in_memory(
    awrtc_mbedtls_svc_key_id_t key, awrtc_psa_key_slot_t **p_slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(key);
    size_t slot_idx;
    awrtc_psa_key_slot_t *slot = NULL;

    if (awrtc_psa_key_id_is_volatile(key_id)) {
        slot = get_volatile_key_slot(key_id);

        /* Check if both the PSA key identifier key_id and the owner
         * identifier of key match those of the key slot. */
        if (slot != NULL &&
            slot->state == AWRTC_PSA_SLOT_FULL &&
            awrtc_mbedtls_svc_key_id_equal(key, slot->attr.id)) {
            status = AWRTC_PSA_SUCCESS;
        } else {
            status = AWRTC_PSA_ERROR_DOES_NOT_EXIST;
        }
    } else {
        if (!awrtc_psa_is_valid_key_id(key, 1)) {
            return AWRTC_PSA_ERROR_INVALID_HANDLE;
        }

        for (slot_idx = 0; slot_idx < PERSISTENT_KEY_CACHE_COUNT; slot_idx++) {
            slot = get_persistent_key_slot(slot_idx);
            /* Only consider slots which are in a full state. */
            if ((slot->state == AWRTC_PSA_SLOT_FULL) &&
                (awrtc_mbedtls_svc_key_id_equal(key, slot->attr.id))) {
                break;
            }
        }
        status = (slot_idx < AWRTC_MBEDTLS_PSA_KEY_SLOT_COUNT) ?
                 AWRTC_PSA_SUCCESS : AWRTC_PSA_ERROR_DOES_NOT_EXIST;
    }

    if (status == AWRTC_PSA_SUCCESS) {
        status = awrtc_psa_register_read(slot);
        if (status == AWRTC_PSA_SUCCESS) {
            *p_slot = slot;
        }
    }

    return status;
}

awrtc_psa_status_t awrtc_psa_initialize_key_slots(void)
{
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    global_data.key_slices[KEY_SLOT_CACHE_SLICE_INDEX] =
        awrtc_mbedtls_calloc(PERSISTENT_KEY_CACHE_COUNT,
                       sizeof(*global_data.key_slices[KEY_SLOT_CACHE_SLICE_INDEX]));
    if (global_data.key_slices[KEY_SLOT_CACHE_SLICE_INDEX] == NULL) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }
#else /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
    /* Nothing to do: program startup and awrtc_psa_wipe_all_key_slots() both
     * guarantee that the key slots are initialized to all-zero, which
     * means that all the key slots are in a valid, empty state. The global
     * data mutex is already held when calling this function, so no need to
     * lock it here, to set the flag. */
#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

    global_data.key_slots_initialized = 1;
    return AWRTC_PSA_SUCCESS;
}

void awrtc_psa_wipe_all_key_slots(void)
{
    for (size_t slice_idx = 0; slice_idx < KEY_SLICE_COUNT; slice_idx++) {
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
        if (global_data.key_slices[slice_idx] == NULL) {
            continue;
        }
#endif  /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
        for (size_t slot_idx = 0; slot_idx < key_slice_length(slice_idx); slot_idx++) {
            awrtc_psa_key_slot_t *slot = get_key_slot(slice_idx, slot_idx);
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
            /* When AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC is disabled, calling
             * awrtc_psa_wipe_key_slot() on an unused slot is useless, but it
             * happens to work (because we flip the state to PENDING_DELETION).
             *
             * When AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC is enabled,
             * awrtc_psa_wipe_key_slot() needs to have a valid slice_index
             * field, but that value might not be correct in a
             * free slot, so we must not call it.
             *
             * Bypass the call to awrtc_psa_wipe_key_slot() if the slot is empty,
             * but only if AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC is enabled, to save
             * a few bytes of code size otherwise.
             */
            if (slot->state == AWRTC_PSA_SLOT_EMPTY) {
                continue;
            }
#endif
            slot->var.occupied.registered_readers = 1;
            slot->state = AWRTC_PSA_SLOT_PENDING_DELETION;
            (void) awrtc_psa_wipe_key_slot(slot);
        }
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
        awrtc_mbedtls_free(global_data.key_slices[slice_idx]);
        global_data.key_slices[slice_idx] = NULL;
#endif  /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
    }

#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    for (size_t slice_idx = 0; slice_idx < KEY_SLOT_VOLATILE_SLICE_COUNT; slice_idx++) {
        global_data.first_free_slot_index[slice_idx] = 0;
    }
#endif  /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

    /* The global data mutex is already held when calling this function. */
    global_data.key_slots_initialized = 0;
}

#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)

static awrtc_psa_status_t awrtc_psa_allocate_volatile_key_slot(awrtc_psa_key_id_t *key_id,
                                                   awrtc_psa_key_slot_t **p_slot)
{
    size_t slice_idx;
    for (slice_idx = 0; slice_idx < KEY_SLOT_VOLATILE_SLICE_COUNT; slice_idx++) {
        if (global_data.first_free_slot_index[slice_idx] != FREE_SLOT_INDEX_NONE) {
            break;
        }
    }
    if (slice_idx == KEY_SLOT_VOLATILE_SLICE_COUNT) {
        return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
    }

    if (global_data.key_slices[slice_idx] == NULL) {
        global_data.key_slices[slice_idx] =
            awrtc_mbedtls_calloc(key_slice_length(slice_idx),
                           sizeof(awrtc_psa_key_slot_t));
        if (global_data.key_slices[slice_idx] == NULL) {
            return AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;
        }
    }
    awrtc_psa_key_slot_t *slice = global_data.key_slices[slice_idx];

    size_t slot_idx = global_data.first_free_slot_index[slice_idx];
    *key_id = volatile_key_id_of_index(slice_idx, slot_idx);

    awrtc_psa_key_slot_t *slot = &slice[slot_idx];
    size_t next_free = slot_idx + 1 + slot->var.free.next_free_relative_to_next;
    if (next_free >= key_slice_length(slice_idx)) {
        next_free = FREE_SLOT_INDEX_NONE;
    }
    global_data.first_free_slot_index[slice_idx] = next_free;
    /* The .next_free field is not meaningful when the slot is not free,
     * so give it the same content as freshly initialized memory. */
    slot->var.free.next_free_relative_to_next = 0;

    awrtc_psa_status_t status = awrtc_psa_key_slot_state_transition(slot,
                                                        AWRTC_PSA_SLOT_EMPTY,
                                                        AWRTC_PSA_SLOT_FILLING);
    if (status != AWRTC_PSA_SUCCESS) {
        /* The only reason for failure is if the slot state was not empty.
         * This indicates that something has gone horribly wrong.
         * In this case, we leave the slot out of the free list, and stop
         * modifying it. This minimizes any further corruption. The slot
         * is a memory leak, but that's a lesser evil. */
        return status;
    }

    *p_slot = slot;
    /* We assert at compile time that the slice index fits in uint8_t. */
    slot->slice_index = (uint8_t) slice_idx;
    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_free_key_slot(size_t slice_idx,
                               awrtc_psa_key_slot_t *slot)
{

    if (slice_idx == KEY_SLOT_CACHE_SLICE_INDEX) {
        /* This is a cache entry. We don't maintain a free list, so
         * there's nothing to do. */
        return AWRTC_PSA_SUCCESS;
    }
    if (slice_idx >= KEY_SLOT_VOLATILE_SLICE_COUNT) {
        return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    }

    awrtc_psa_key_slot_t *slice = global_data.key_slices[slice_idx];
    awrtc_psa_key_slot_t *slice_end = slice + key_slice_length(slice_idx);
    if (slot < slice || slot >= slice_end) {
        /* The slot isn't actually in the slice! We can't detect that
         * condition for sure, because the pointer comparison itself is
         * undefined behavior in that case. That same condition makes the
         * subtraction to calculate the slot index also UB.
         * Give up now to avoid causing further corruption.
         */
        return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    }
    size_t slot_idx = slot - slice;

    size_t next_free = global_data.first_free_slot_index[slice_idx];
    if (next_free >= key_slice_length(slice_idx)) {
        /* The slot was full. The newly freed slot thus becomes the
         * end of the free list. */
        next_free = key_slice_length(slice_idx);
    }
    global_data.first_free_slot_index[slice_idx] = slot_idx;
    slot->var.free.next_free_relative_to_next =
        (int32_t) next_free - (int32_t) slot_idx - 1;

    return AWRTC_PSA_SUCCESS;
}
#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

awrtc_psa_status_t awrtc_psa_reserve_free_key_slot(awrtc_psa_key_id_t *volatile_key_id,
                                       awrtc_psa_key_slot_t **p_slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    size_t slot_idx;
    awrtc_psa_key_slot_t *selected_slot, *unused_persistent_key_slot;

    if (!awrtc_psa_get_key_slots_initialized()) {
        status = AWRTC_PSA_ERROR_BAD_STATE;
        goto error;
    }

#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
    if (volatile_key_id != NULL) {
        return awrtc_psa_allocate_volatile_key_slot(volatile_key_id, p_slot);
    }
#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

    /* With a dynamic key store, allocate an entry in the cache slice,
     * applicable only to non-volatile keys that get cached in RAM.
     * With a static key store, allocate an entry in the sole slice,
     * applicable to all keys. */
    selected_slot = unused_persistent_key_slot = NULL;
    for (slot_idx = 0; slot_idx < PERSISTENT_KEY_CACHE_COUNT; slot_idx++) {
        awrtc_psa_key_slot_t *slot = get_key_slot(KEY_SLOT_CACHE_SLICE_INDEX, slot_idx);
        if (slot->state == AWRTC_PSA_SLOT_EMPTY) {
            selected_slot = slot;
            break;
        }

        if ((unused_persistent_key_slot == NULL) &&
            (slot->state == AWRTC_PSA_SLOT_FULL) &&
            (!awrtc_psa_key_slot_has_readers(slot)) &&
            (!AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime))) {
            unused_persistent_key_slot = slot;
        }
    }

    /*
     * If there is no unused key slot and there is at least one unlocked key
     * slot containing the description of a persistent key, recycle the first
     * such key slot we encountered. If we later need to operate on the
     * persistent key we are evicting now, we will reload its description from
     * storage.
     */
    if ((selected_slot == NULL) &&
        (unused_persistent_key_slot != NULL)) {
        selected_slot = unused_persistent_key_slot;
        awrtc_psa_register_read(selected_slot);
        status = awrtc_psa_wipe_key_slot(selected_slot);
        if (status != AWRTC_PSA_SUCCESS) {
            goto error;
        }
    }

    if (selected_slot != NULL) {
        status = awrtc_psa_key_slot_state_transition(selected_slot, AWRTC_PSA_SLOT_EMPTY,
                                               AWRTC_PSA_SLOT_FILLING);
        if (status != AWRTC_PSA_SUCCESS) {
            goto error;
        }

#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
        selected_slot->slice_index = KEY_SLOT_CACHE_SLICE_INDEX;
#endif /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */

#if !defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
        if (volatile_key_id != NULL) {
            /* Refresh slot_idx, for when the slot is not the original
             * selected_slot but rather unused_persistent_key_slot.  */
            slot_idx = selected_slot - global_data.key_slots;
            *volatile_key_id = AWRTC_PSA_KEY_ID_VOLATILE_MIN + (awrtc_psa_key_id_t) slot_idx;
        }
#endif
        *p_slot = selected_slot;

        return AWRTC_PSA_SUCCESS;
    }
    status = AWRTC_PSA_ERROR_INSUFFICIENT_MEMORY;

error:
    *p_slot = NULL;

    return status;
}

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C)
static awrtc_psa_status_t awrtc_psa_load_persistent_key_into_slot(awrtc_psa_key_slot_t *slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_SUCCESS;
    uint8_t *key_data = NULL;
    size_t key_data_length = 0;
    awrtc_psa_key_id_t key_id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id);

    /* Do not try to load a persistent key whose ID is in the volatile range. */
    if ((key_id >= AWRTC_PSA_KEY_ID_VOLATILE_MIN) && (key_id <= AWRTC_PSA_KEY_ID_VOLATILE_MAX)) {
        return AWRTC_PSA_ERROR_DOES_NOT_EXIST;
    }

    status = awrtc_psa_load_persistent_key(&slot->attr,
                                     &key_data, &key_data_length);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)
    /* Special handling is required for loading keys associated with a
     * dynamically registered SE interface. */
    const awrtc_psa_drv_se_t *drv;
    awrtc_psa_drv_se_context_t *drv_context;
    if (awrtc_psa_get_se_driver(slot->attr.lifetime, &drv, &drv_context)) {
        awrtc_psa_se_key_data_storage_t *data;

        if (key_data_length != sizeof(*data)) {
            status = AWRTC_PSA_ERROR_DATA_INVALID;
            goto exit;
        }
        data = (awrtc_psa_se_key_data_storage_t *) key_data;
        status = awrtc_psa_copy_key_material_into_slot(
            slot, data->slot_number, sizeof(data->slot_number));
        goto exit;
    }
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_SE_C */

    status = awrtc_psa_copy_key_material_into_slot(slot, key_data, key_data_length);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

exit:
    awrtc_psa_free_persistent_key_data(key_data, key_data_length);
    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C */

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)

static awrtc_psa_status_t awrtc_psa_load_builtin_key_into_slot(awrtc_psa_key_slot_t *slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_attributes_t attributes = AWRTC_PSA_KEY_ATTRIBUTES_INIT;
    awrtc_psa_key_lifetime_t lifetime = AWRTC_PSA_KEY_LIFETIME_VOLATILE;
    awrtc_psa_drv_slot_number_t slot_number = 0;
    size_t key_buffer_size = 0;
    size_t key_buffer_length = 0;

    if (!awrtc_psa_key_id_is_builtin(
            AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id))) {
        return AWRTC_PSA_ERROR_DOES_NOT_EXIST;
    }

    /* Check the platform function to see whether this key actually exists */
    status = awrtc_mbedtls_psa_platform_get_builtin_key(
        slot->attr.id, &lifetime, &slot_number);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    /* Set required key attributes to ensure get_builtin_key can retrieve the
     * full attributes. */
    awrtc_psa_set_key_id(&attributes, slot->attr.id);
    awrtc_psa_set_key_lifetime(&attributes, lifetime);

    /* Get the full key attributes from the driver in order to be able to
     * calculate the required buffer size. */
    status = awrtc_psa_driver_wrapper_get_builtin_key(
        slot_number, &attributes,
        NULL, 0, NULL);
    if (status != AWRTC_PSA_ERROR_BUFFER_TOO_SMALL) {
        /* Builtin keys cannot be defined by the attributes alone */
        if (status == AWRTC_PSA_SUCCESS) {
            status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
        }
        return status;
    }

    /* If the key should exist according to the platform, then ask the driver
     * what its expected size is. */
    status = awrtc_psa_driver_wrapper_get_key_buffer_size(&attributes,
                                                    &key_buffer_size);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    /* Allocate a buffer of the required size and load the builtin key directly
     * into the (now properly sized) slot buffer. */
    status = awrtc_psa_allocate_buffer_to_slot(slot, key_buffer_size);
    if (status != AWRTC_PSA_SUCCESS) {
        return status;
    }

    status = awrtc_psa_driver_wrapper_get_builtin_key(
        slot_number, &attributes,
        slot->key.data, slot->key.bytes, &key_buffer_length);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }

    /* Copy actual key length and core attributes into the slot on success */
    slot->key.bytes = key_buffer_length;
    slot->attr = attributes;
exit:
    if (status != AWRTC_PSA_SUCCESS) {
        awrtc_psa_remove_key_data_from_memory(slot);
    }
    return status;
}
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

awrtc_psa_status_t awrtc_psa_get_and_lock_key_slot(awrtc_mbedtls_svc_key_id_t key,
                                       awrtc_psa_key_slot_t **p_slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;

    *p_slot = NULL;
    if (!awrtc_psa_get_key_slots_initialized()) {
        return AWRTC_PSA_ERROR_BAD_STATE;
    }

#if defined(AWRTC_MBEDTLS_THREADING_C)
    /* We need to set status as success, otherwise CORRUPTION_DETECTED
     * would be returned if the lock fails. */
    status = AWRTC_PSA_SUCCESS;
    /* If the key is persistent and not loaded, we cannot unlock the mutex
     * between checking if the key is loaded and setting the slot as FULL,
     * as otherwise another thread may load and then destroy the key
     * in the meantime. */
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_lock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    /*
     * On success, the pointer to the slot is passed directly to the caller
     * thus no need to unlock the key slot here.
     */
    status = awrtc_psa_get_and_lock_key_slot_in_memory(key, p_slot);
    if (status != AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
#if defined(AWRTC_MBEDTLS_THREADING_C)
        AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                                  &awrtc_mbedtls_threading_key_slot_mutex));
#endif
        return status;
    }

    /* Loading keys from storage requires support for such a mechanism */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C) || \
    defined(AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)

    status = awrtc_psa_reserve_free_key_slot(NULL, p_slot);
    if (status != AWRTC_PSA_SUCCESS) {
#if defined(AWRTC_MBEDTLS_THREADING_C)
        AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                                  &awrtc_mbedtls_threading_key_slot_mutex));
#endif
        return status;
    }

    (*p_slot)->attr.id = key;
    (*p_slot)->attr.lifetime = AWRTC_PSA_KEY_LIFETIME_PERSISTENT;

    status = AWRTC_PSA_ERROR_DOES_NOT_EXIST;
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    /* Load keys in the 'builtin' range through their own interface */
    status = awrtc_psa_load_builtin_key_into_slot(*p_slot);
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C)
    if (status == AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
        status = awrtc_psa_load_persistent_key_into_slot(*p_slot);
    }
#endif /* defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C) */

    if (status != AWRTC_PSA_SUCCESS) {
        awrtc_psa_wipe_key_slot(*p_slot);

        /* If the key does not exist, we need to return
         * AWRTC_PSA_ERROR_INVALID_HANDLE. */
        if (status == AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
            status = AWRTC_PSA_ERROR_INVALID_HANDLE;
        }
    } else {
        /* Add implicit usage flags. */
        awrtc_psa_extend_key_usage_flags(&(*p_slot)->attr.policy.usage);

        awrtc_psa_key_slot_state_transition((*p_slot), AWRTC_PSA_SLOT_FILLING,
                                      AWRTC_PSA_SLOT_FULL);
        status = awrtc_psa_register_read(*p_slot);
    }

#else /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C || AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    status = AWRTC_PSA_ERROR_INVALID_HANDLE;
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C || AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */

    if (status != AWRTC_PSA_SUCCESS) {
        *p_slot = NULL;
    }
#if defined(AWRTC_MBEDTLS_THREADING_C)
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    return status;
}

awrtc_psa_status_t awrtc_psa_unregister_read(awrtc_psa_key_slot_t *slot)
{
    if (slot == NULL) {
        return AWRTC_PSA_SUCCESS;
    }
    if ((slot->state != AWRTC_PSA_SLOT_FULL) &&
        (slot->state != AWRTC_PSA_SLOT_PENDING_DELETION)) {
        return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    }

    /* If we are the last reader and the slot is marked for deletion,
     * we must wipe the slot here. */
    if ((slot->state == AWRTC_PSA_SLOT_PENDING_DELETION) &&
        (slot->var.occupied.registered_readers == 1)) {
        return awrtc_psa_wipe_key_slot(slot);
    }

    if (awrtc_psa_key_slot_has_readers(slot)) {
        slot->var.occupied.registered_readers--;
        return AWRTC_PSA_SUCCESS;
    }

    /*
     * As the return error code may not be handled in case of multiple errors,
     * do our best to report if there are no registered readers. Assert with
     * AWRTC_MBEDTLS_TEST_HOOK_TEST_ASSERT that there are registered readers:
     * if the AWRTC_MBEDTLS_TEST_HOOKS configuration option is enabled and
     * the function is called as part of the execution of a test suite, the
     * execution of the test suite is stopped in error if the assertion fails.
     */
    AWRTC_MBEDTLS_TEST_HOOK_TEST_ASSERT(awrtc_psa_key_slot_has_readers(slot));
    return AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
}

awrtc_psa_status_t awrtc_psa_unregister_read_under_mutex(awrtc_psa_key_slot_t *slot)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
#if defined(AWRTC_MBEDTLS_THREADING_C)
    /* We need to set status as success, otherwise CORRUPTION_DETECTED
     * would be returned if the lock fails. */
    status = AWRTC_PSA_SUCCESS;
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_lock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    status = awrtc_psa_unregister_read(slot);
#if defined(AWRTC_MBEDTLS_THREADING_C)
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    return status;
}

awrtc_psa_status_t awrtc_psa_validate_key_location(awrtc_psa_key_lifetime_t lifetime,
                                       awrtc_psa_se_drv_table_entry_t **p_drv)
{
    if (awrtc_psa_key_lifetime_is_external(lifetime)) {
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_SE_C)
        /* Check whether a driver is registered against this lifetime */
        awrtc_psa_se_drv_table_entry_t *driver = awrtc_psa_get_se_driver_entry(lifetime);
        if (driver != NULL) {
            if (p_drv != NULL) {
                *p_drv = driver;
            }
            return AWRTC_PSA_SUCCESS;
        }
#else /* AWRTC_MBEDTLS_PSA_CRYPTO_SE_C */
        (void) p_drv;
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_SE_C */

        /* Key location for external keys gets checked by the wrapper */
        return AWRTC_PSA_SUCCESS;
    } else {
        /* Local/internal keys are always valid */
        return AWRTC_PSA_SUCCESS;
    }
}

awrtc_psa_status_t awrtc_psa_validate_key_persistence(awrtc_psa_key_lifetime_t lifetime)
{
    if (AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(lifetime)) {
        /* Volatile keys are always supported */
        return AWRTC_PSA_SUCCESS;
    } else {
        /* Persistent keys require storage support */
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C)
        if (AWRTC_PSA_KEY_LIFETIME_IS_READ_ONLY(lifetime)) {
            return AWRTC_PSA_ERROR_INVALID_ARGUMENT;
        } else {
            return AWRTC_PSA_SUCCESS;
        }
#else /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C */
        return AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* !AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C */
    }
}

awrtc_psa_status_t awrtc_psa_open_key(awrtc_mbedtls_svc_key_id_t key, awrtc_psa_key_handle_t *handle)
{
#if defined(AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C) || \
    defined(AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS)
    awrtc_psa_status_t status;
    awrtc_psa_key_slot_t *slot;

    status = awrtc_psa_get_and_lock_key_slot(key, &slot);
    if (status != AWRTC_PSA_SUCCESS) {
        *handle = AWRTC_PSA_KEY_HANDLE_INIT;
        if (status == AWRTC_PSA_ERROR_INVALID_HANDLE) {
            status = AWRTC_PSA_ERROR_DOES_NOT_EXIST;
        }

        return status;
    }

    *handle = key;

    return awrtc_psa_unregister_read_under_mutex(slot);

#else /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C || AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
    (void) key;
    *handle = AWRTC_PSA_KEY_HANDLE_INIT;
    return AWRTC_PSA_ERROR_NOT_SUPPORTED;
#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_STORAGE_C || AWRTC_MBEDTLS_PSA_CRYPTO_BUILTIN_KEYS */
}

awrtc_psa_status_t awrtc_psa_close_key(awrtc_psa_key_handle_t handle)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_slot_t *slot;

    if (awrtc_psa_key_handle_is_null(handle)) {
        return AWRTC_PSA_SUCCESS;
    }

#if defined(AWRTC_MBEDTLS_THREADING_C)
    /* We need to set status as success, otherwise CORRUPTION_DETECTED
     * would be returned if the lock fails. */
    status = AWRTC_PSA_SUCCESS;
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_lock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    status = awrtc_psa_get_and_lock_key_slot_in_memory(handle, &slot);
    if (status != AWRTC_PSA_SUCCESS) {
        if (status == AWRTC_PSA_ERROR_DOES_NOT_EXIST) {
            status = AWRTC_PSA_ERROR_INVALID_HANDLE;
        }
#if defined(AWRTC_MBEDTLS_THREADING_C)
        AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                                  &awrtc_mbedtls_threading_key_slot_mutex));
#endif
        return status;
    }

    if (slot->var.occupied.registered_readers == 1) {
        status = awrtc_psa_wipe_key_slot(slot);
    } else {
        status = awrtc_psa_unregister_read(slot);
    }
#if defined(AWRTC_MBEDTLS_THREADING_C)
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif

    return status;
}

awrtc_psa_status_t awrtc_psa_purge_key(awrtc_mbedtls_svc_key_id_t key)
{
    awrtc_psa_status_t status = AWRTC_PSA_ERROR_CORRUPTION_DETECTED;
    awrtc_psa_key_slot_t *slot;

#if defined(AWRTC_MBEDTLS_THREADING_C)
    /* We need to set status as success, otherwise CORRUPTION_DETECTED
     * would be returned if the lock fails. */
    status = AWRTC_PSA_SUCCESS;
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_lock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif
    status = awrtc_psa_get_and_lock_key_slot_in_memory(key, &slot);
    if (status != AWRTC_PSA_SUCCESS) {
#if defined(AWRTC_MBEDTLS_THREADING_C)
        AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                                  &awrtc_mbedtls_threading_key_slot_mutex));
#endif
        return status;
    }

    if ((!AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)) &&
        (slot->var.occupied.registered_readers == 1)) {
        status = awrtc_psa_wipe_key_slot(slot);
    } else {
        status = awrtc_psa_unregister_read(slot);
    }
#if defined(AWRTC_MBEDTLS_THREADING_C)
    AWRTC_PSA_THREADING_CHK_RET(awrtc_mbedtls_mutex_unlock(
                              &awrtc_mbedtls_threading_key_slot_mutex));
#endif

    return status;
}

void awrtc_mbedtls_psa_get_stats(awrtc_mbedtls_psa_stats_t *stats)
{
    memset(stats, 0, sizeof(*stats));

    for (size_t slice_idx = 0; slice_idx < KEY_SLICE_COUNT; slice_idx++) {
#if defined(AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC)
        if (global_data.key_slices[slice_idx] == NULL) {
            continue;
        }
#endif  /* AWRTC_MBEDTLS_PSA_KEY_STORE_DYNAMIC */
        for (size_t slot_idx = 0; slot_idx < key_slice_length(slice_idx); slot_idx++) {
            const awrtc_psa_key_slot_t *slot = get_key_slot(slice_idx, slot_idx);
            if (slot->state == AWRTC_PSA_SLOT_EMPTY) {
                ++stats->empty_slots;
                continue;
            }
            if (awrtc_psa_key_slot_has_readers(slot)) {
                ++stats->locked_slots;
            }
            if (AWRTC_PSA_KEY_LIFETIME_IS_VOLATILE(slot->attr.lifetime)) {
                ++stats->volatile_slots;
            } else {
                awrtc_psa_key_id_t id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id);
                ++stats->persistent_slots;
                if (id > stats->max_open_internal_key_id) {
                    stats->max_open_internal_key_id = id;
                }
            }
            if (AWRTC_PSA_KEY_LIFETIME_GET_LOCATION(slot->attr.lifetime) !=
                AWRTC_PSA_KEY_LOCATION_LOCAL_STORAGE) {
                awrtc_psa_key_id_t id = AWRTC_MBEDTLS_SVC_KEY_ID_GET_KEY_ID(slot->attr.id);
                ++stats->external_slots;
                if (id > stats->max_open_external_key_id) {
                    stats->max_open_external_key_id = id;
                }
            }
        }
    }
}

#endif /* AWRTC_MBEDTLS_PSA_CRYPTO_C */
