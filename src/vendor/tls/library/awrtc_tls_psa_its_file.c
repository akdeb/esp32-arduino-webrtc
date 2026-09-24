/*
 *  PSA ITS simulator over stdio files.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include "common.h"

#if defined(AWRTC_MBEDTLS_PSA_ITS_FILE_C)

#include "../include/mbedtls/platform.h"

#if defined(_WIN32)
#include <windows.h>
#endif

#include "psa_crypto_its.h"

#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#if !defined(AWRTC_PSA_ITS_STORAGE_PREFIX)
#define AWRTC_PSA_ITS_STORAGE_PREFIX ""
#endif

#define AWRTC_PSA_ITS_STORAGE_FILENAME_PATTERN "%08x%08x"
#define AWRTC_PSA_ITS_STORAGE_SUFFIX ".awrtc_psa_its"
#define AWRTC_PSA_ITS_STORAGE_FILENAME_LENGTH         \
    (sizeof(AWRTC_PSA_ITS_STORAGE_PREFIX) - 1 +    /*prefix without terminating 0*/ \
     16 +  /*UID (64-bit number in hex)*/                               \
     sizeof(AWRTC_PSA_ITS_STORAGE_SUFFIX) - 1 +    /*suffix without terminating 0*/ \
     1 /*terminating null byte*/)
#define AWRTC_PSA_ITS_STORAGE_TEMP \
    AWRTC_PSA_ITS_STORAGE_PREFIX "tempfile" AWRTC_PSA_ITS_STORAGE_SUFFIX

/* The maximum value of awrtc_psa_storage_info_t.size */
#define AWRTC_PSA_ITS_MAX_SIZE 0xffffffff

#define AWRTC_PSA_ITS_MAGIC_STRING "PSA\0ITS\0"
#define AWRTC_PSA_ITS_MAGIC_LENGTH 8

/* As rename fails on Windows if the new filepath already exists,
 * use MoveFileExA with the MOVEFILE_REPLACE_EXISTING flag instead.
 * Returns 0 on success, nonzero on failure. */
#if defined(_WIN32)
#define rename_replace_existing(oldpath, newpath) \
    (!MoveFileExA(oldpath, newpath, MOVEFILE_REPLACE_EXISTING))
#else
#define rename_replace_existing(oldpath, newpath) rename(oldpath, newpath)
#endif

typedef struct {
    uint8_t magic[AWRTC_PSA_ITS_MAGIC_LENGTH];
    uint8_t size[sizeof(uint32_t)];
    uint8_t flags[sizeof(awrtc_psa_storage_create_flags_t)];
} awrtc_psa_its_file_header_t;

static void awrtc_psa_its_fill_filename(awrtc_psa_storage_uid_t uid, char *filename)
{
    /* Break up the UID into two 32-bit pieces so as not to rely on
     * long long support in snprintf. */
    awrtc_mbedtls_snprintf(filename, AWRTC_PSA_ITS_STORAGE_FILENAME_LENGTH,
                     "%s" AWRTC_PSA_ITS_STORAGE_FILENAME_PATTERN "%s",
                     AWRTC_PSA_ITS_STORAGE_PREFIX,
                     (unsigned) (uid >> 32),
                     (unsigned) (uid & 0xffffffff),
                     AWRTC_PSA_ITS_STORAGE_SUFFIX);
}

static awrtc_psa_status_t awrtc_psa_its_read_file(awrtc_psa_storage_uid_t uid,
                                      struct awrtc_psa_storage_info_t *p_info,
                                      FILE **p_stream)
{
    char filename[AWRTC_PSA_ITS_STORAGE_FILENAME_LENGTH];
    awrtc_psa_its_file_header_t header;
    size_t n;

    *p_stream = NULL;
    awrtc_psa_its_fill_filename(uid, filename);
    *p_stream = fopen(filename, "rb");
    if (*p_stream == NULL) {
        return AWRTC_PSA_ERROR_DOES_NOT_EXIST;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    awrtc_mbedtls_setbuf(*p_stream, NULL);

    n = fread(&header, 1, sizeof(header), *p_stream);
    if (n != sizeof(header)) {
        return AWRTC_PSA_ERROR_DATA_CORRUPT;
    }
    if (memcmp(header.magic, AWRTC_PSA_ITS_MAGIC_STRING,
               AWRTC_PSA_ITS_MAGIC_LENGTH) != 0) {
        return AWRTC_PSA_ERROR_DATA_CORRUPT;
    }

    p_info->size  = AWRTC_MBEDTLS_GET_UINT32_LE(header.size, 0);
    p_info->flags = AWRTC_MBEDTLS_GET_UINT32_LE(header.flags, 0);

    return AWRTC_PSA_SUCCESS;
}

awrtc_psa_status_t awrtc_psa_its_get_info(awrtc_psa_storage_uid_t uid,
                              struct awrtc_psa_storage_info_t *p_info)
{
    awrtc_psa_status_t status;
    FILE *stream = NULL;
    status = awrtc_psa_its_read_file(uid, p_info, &stream);
    if (stream != NULL) {
        fclose(stream);
    }
    return status;
}

awrtc_psa_status_t awrtc_psa_its_get(awrtc_psa_storage_uid_t uid,
                         uint32_t data_offset,
                         uint32_t data_length,
                         void *p_data,
                         size_t *p_data_length)
{
    awrtc_psa_status_t status;
    FILE *stream = NULL;
    size_t n;
    struct awrtc_psa_storage_info_t info;

    status = awrtc_psa_its_read_file(uid, &info, &stream);
    if (status != AWRTC_PSA_SUCCESS) {
        goto exit;
    }
    status = AWRTC_PSA_ERROR_INVALID_ARGUMENT;
    if (data_offset + data_length < data_offset) {
        goto exit;
    }
#if SIZE_MAX < 0xffffffff
    if (data_offset + data_length > SIZE_MAX) {
        goto exit;
    }
#endif
    if (data_offset + data_length > info.size) {
        goto exit;
    }

    status = AWRTC_PSA_ERROR_STORAGE_FAILURE;
#if LONG_MAX < 0xffffffff
    while (data_offset > LONG_MAX) {
        if (fseek(stream, LONG_MAX, SEEK_CUR) != 0) {
            goto exit;
        }
        data_offset -= LONG_MAX;
    }
#endif
    if (fseek(stream, data_offset, SEEK_CUR) != 0) {
        goto exit;
    }
    n = fread(p_data, 1, data_length, stream);
    if (n != data_length) {
        goto exit;
    }
    status = AWRTC_PSA_SUCCESS;
    if (p_data_length != NULL) {
        *p_data_length = n;
    }

exit:
    if (stream != NULL) {
        fclose(stream);
    }
    return status;
}

awrtc_psa_status_t awrtc_psa_its_set(awrtc_psa_storage_uid_t uid,
                         uint32_t data_length,
                         const void *p_data,
                         awrtc_psa_storage_create_flags_t create_flags)
{
    if (uid == 0) {
        return AWRTC_PSA_ERROR_INVALID_HANDLE;
    }

    awrtc_psa_status_t status = AWRTC_PSA_ERROR_STORAGE_FAILURE;
    char filename[AWRTC_PSA_ITS_STORAGE_FILENAME_LENGTH];
    FILE *stream = NULL;
    awrtc_psa_its_file_header_t header;
    size_t n;

    memcpy(header.magic, AWRTC_PSA_ITS_MAGIC_STRING, AWRTC_PSA_ITS_MAGIC_LENGTH);
    AWRTC_MBEDTLS_PUT_UINT32_LE(data_length, header.size, 0);
    AWRTC_MBEDTLS_PUT_UINT32_LE(create_flags, header.flags, 0);

    awrtc_psa_its_fill_filename(uid, filename);
    stream = fopen(AWRTC_PSA_ITS_STORAGE_TEMP, "wb");

    if (stream == NULL) {
        goto exit;
    }

    /* Ensure no stdio buffering of secrets, as such buffers cannot be wiped. */
    awrtc_mbedtls_setbuf(stream, NULL);

    status = AWRTC_PSA_ERROR_INSUFFICIENT_STORAGE;
    n = fwrite(&header, 1, sizeof(header), stream);
    if (n != sizeof(header)) {
        goto exit;
    }
    if (data_length != 0) {
        n = fwrite(p_data, 1, data_length, stream);
        if (n != data_length) {
            goto exit;
        }
    }
    status = AWRTC_PSA_SUCCESS;

exit:
    if (stream != NULL) {
        int ret = fclose(stream);
        if (status == AWRTC_PSA_SUCCESS && ret != 0) {
            status = AWRTC_PSA_ERROR_INSUFFICIENT_STORAGE;
        }
    }
    if (status == AWRTC_PSA_SUCCESS) {
        if (rename_replace_existing(AWRTC_PSA_ITS_STORAGE_TEMP, filename) != 0) {
            status = AWRTC_PSA_ERROR_STORAGE_FAILURE;
        }
    }
    /* The temporary file may still exist, but only in failure cases where
     * we're already reporting an error. So there's nothing we can do on
     * failure. If the function succeeded, and in some error cases, the
     * temporary file doesn't exist and so remove() is expected to fail.
     * Thus we just ignore the return status of remove(). */
    (void) remove(AWRTC_PSA_ITS_STORAGE_TEMP);
    return status;
}

awrtc_psa_status_t awrtc_psa_its_remove(awrtc_psa_storage_uid_t uid)
{
    char filename[AWRTC_PSA_ITS_STORAGE_FILENAME_LENGTH];
    FILE *stream;
    awrtc_psa_its_fill_filename(uid, filename);
    stream = fopen(filename, "rb");
    if (stream == NULL) {
        return AWRTC_PSA_ERROR_DOES_NOT_EXIST;
    }
    fclose(stream);
    if (remove(filename) != 0) {
        return AWRTC_PSA_ERROR_STORAGE_FAILURE;
    }
    return AWRTC_PSA_SUCCESS;
}

#endif /* AWRTC_MBEDTLS_PSA_ITS_FILE_C */
