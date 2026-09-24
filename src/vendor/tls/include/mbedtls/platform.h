/**
 * \file platform.h
 *
 * \brief This file contains the definitions and functions of the
 *        Mbed TLS platform abstraction layer.
 *
 *        The platform abstraction layer removes the need for the library
 *        to directly link to standard C library functions or operating
 *        system services, making the library easier to port and embed.
 *        Application developers and users of the library can provide their own
 *        implementations of these functions, or implementations specific to
 *        their platform, which can be statically linked to the library or
 *        dynamically configured at runtime.
 *
 *        When all compilation options related to platform abstraction are
 *        disabled, this header just defines `awrtc_mbedtls_xxx` function names
 *        as aliases to the standard `xxx` function.
 *
 *        Most modules in the library and example programs are expected to
 *        include this header.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */
#ifndef AWRTC_MBEDTLS_PLATFORM_H
#define AWRTC_MBEDTLS_PLATFORM_H
#include "private_access.h"

#include "build_info.h"

#if defined(AWRTC_MBEDTLS_HAVE_TIME)
#include "platform_time.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \name SECTION: Module settings
 *
 * The configuration options you can set for this module are in this section.
 * Either change them in awrtc_mbedtls_config.h or define them on the compiler command line.
 * \{
 */

/* The older Microsoft Windows common runtime provides non-conforming
 * implementations of some standard library functions, including snprintf
 * and vsnprintf. This affects MSVC and MinGW builds.
 */
#if defined(__MINGW32__) || (defined(_MSC_VER) && _MSC_VER <= 1900)
#define AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF
#define AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF
#endif

#if !defined(AWRTC_MBEDTLS_PLATFORM_NO_STD_FUNCTIONS)
#include <stdio.h>
#include <stdlib.h>
#if defined(AWRTC_MBEDTLS_HAVE_TIME)
#include <time.h>
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_SNPRINTF)
#if defined(AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
#define AWRTC_MBEDTLS_PLATFORM_STD_SNPRINTF   awrtc_mbedtls_platform_win32_snprintf /**< The default \c snprintf function to use.  */
#else
#define AWRTC_MBEDTLS_PLATFORM_STD_SNPRINTF   snprintf /**< The default \c snprintf function to use.  */
#endif
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_VSNPRINTF)
#if defined(AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#define AWRTC_MBEDTLS_PLATFORM_STD_VSNPRINTF   awrtc_mbedtls_platform_win32_vsnprintf /**< The default \c vsnprintf function to use.  */
#else
#define AWRTC_MBEDTLS_PLATFORM_STD_VSNPRINTF   vsnprintf /**< The default \c vsnprintf function to use.  */
#endif
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_PRINTF)
#define AWRTC_MBEDTLS_PLATFORM_STD_PRINTF   printf /**< The default \c printf function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_FPRINTF)
#define AWRTC_MBEDTLS_PLATFORM_STD_FPRINTF fprintf /**< The default \c fprintf function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_CALLOC)
#define AWRTC_MBEDTLS_PLATFORM_STD_CALLOC   calloc /**< The default \c calloc function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_FREE)
#define AWRTC_MBEDTLS_PLATFORM_STD_FREE       free /**< The default \c free function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_SETBUF)
#define AWRTC_MBEDTLS_PLATFORM_STD_SETBUF   setbuf /**< The default \c setbuf function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_EXIT)
#define AWRTC_MBEDTLS_PLATFORM_STD_EXIT      exit /**< The default \c exit function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_TIME)
#define AWRTC_MBEDTLS_PLATFORM_STD_TIME       time    /**< The default \c time function to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define AWRTC_MBEDTLS_PLATFORM_STD_EXIT_SUCCESS  EXIT_SUCCESS /**< The default exit value to use. */
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define AWRTC_MBEDTLS_PLATFORM_STD_EXIT_FAILURE  EXIT_FAILURE /**< The default exit value to use. */
#endif
#if defined(AWRTC_MBEDTLS_FS_IO)
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_READ)
#define AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_READ   awrtc_mbedtls_platform_std_nv_seed_read
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_WRITE)
#define AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_WRITE  awrtc_mbedtls_platform_std_nv_seed_write
#endif
#if !defined(AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_FILE)
#define AWRTC_MBEDTLS_PLATFORM_STD_NV_SEED_FILE   "seedfile"
#endif
#endif /* AWRTC_MBEDTLS_FS_IO */
#else /* AWRTC_MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */
#if defined(AWRTC_MBEDTLS_PLATFORM_STD_MEM_HDR)
#include AWRTC_MBEDTLS_PLATFORM_STD_MEM_HDR
#endif
#endif /* AWRTC_MBEDTLS_PLATFORM_NO_STD_FUNCTIONS */

/* Enable certain documented defines only when generating doxygen to avoid
 * an "unrecognized define" error. */
#if defined(__DOXYGEN__) && !defined(AWRTC_MBEDTLS_PLATFORM_STD_CALLOC)
#define AWRTC_MBEDTLS_PLATFORM_STD_CALLOC
#endif

#if defined(__DOXYGEN__) && !defined(AWRTC_MBEDTLS_PLATFORM_STD_FREE)
#define AWRTC_MBEDTLS_PLATFORM_STD_FREE
#endif

/** \} name SECTION: Module settings */

/*
 * The function pointers for calloc and free.
 * Please see AWRTC_MBEDTLS_PLATFORM_STD_CALLOC and AWRTC_MBEDTLS_PLATFORM_STD_FREE
 * in awrtc_mbedtls_config.h for more information about behaviour and requirements.
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_MEMORY)
#if defined(AWRTC_MBEDTLS_PLATFORM_FREE_MACRO) && \
    defined(AWRTC_MBEDTLS_PLATFORM_CALLOC_MACRO)
#undef awrtc_mbedtls_free
#undef awrtc_mbedtls_calloc
#define awrtc_mbedtls_free       AWRTC_MBEDTLS_PLATFORM_FREE_MACRO
#define awrtc_mbedtls_calloc     AWRTC_MBEDTLS_PLATFORM_CALLOC_MACRO
#else
/* For size_t */
#include <stddef.h>
extern void *awrtc_mbedtls_calloc(size_t n, size_t size);
extern void awrtc_mbedtls_free(void *ptr);

/**
 * \brief               This function dynamically sets the memory-management
 *                      functions used by the library, during runtime.
 *
 * \param calloc_func   The \c calloc function implementation.
 * \param free_func     The \c free function implementation.
 *
 * \return              \c 0.
 */
int awrtc_mbedtls_platform_set_calloc_free(void *(*calloc_func)(size_t, size_t),
                                     void (*free_func)(void *));
#endif /* AWRTC_MBEDTLS_PLATFORM_FREE_MACRO && AWRTC_MBEDTLS_PLATFORM_CALLOC_MACRO */
#else /* !AWRTC_MBEDTLS_PLATFORM_MEMORY */
#undef awrtc_mbedtls_free
#undef awrtc_mbedtls_calloc
#define awrtc_mbedtls_free       free
#define awrtc_mbedtls_calloc     calloc
#endif /* AWRTC_MBEDTLS_PLATFORM_MEMORY && !AWRTC_MBEDTLS_PLATFORM_{FREE,CALLOC}_MACRO */

/*
 * The function pointers for fprintf
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_FPRINTF_ALT)
/* We need FILE * */
#include <stdio.h>
extern int (*awrtc_mbedtls_fprintf)(FILE *stream, const char *format, ...);

/**
 * \brief                This function dynamically configures the fprintf
 *                       function that is called when the
 *                       awrtc_mbedtls_fprintf() function is invoked by the library.
 *
 * \param fprintf_func   The \c fprintf function implementation.
 *
 * \return               \c 0.
 */
int awrtc_mbedtls_platform_set_fprintf(int (*fprintf_func)(FILE *stream, const char *,
                                                     ...));
#else
#undef awrtc_mbedtls_fprintf
#if defined(AWRTC_MBEDTLS_PLATFORM_FPRINTF_MACRO)
#define awrtc_mbedtls_fprintf    AWRTC_MBEDTLS_PLATFORM_FPRINTF_MACRO
#else
#define awrtc_mbedtls_fprintf    fprintf
#endif /* AWRTC_MBEDTLS_PLATFORM_FPRINTF_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_FPRINTF_ALT */

/*
 * The function pointers for printf
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_PRINTF_ALT)
extern int (*awrtc_mbedtls_printf)(const char *format, ...);

/**
 * \brief               This function dynamically configures the snprintf
 *                      function that is called when the awrtc_mbedtls_snprintf()
 *                      function is invoked by the library.
 *
 * \param printf_func   The \c printf function implementation.
 *
 * \return              \c 0 on success.
 */
int awrtc_mbedtls_platform_set_printf(int (*printf_func)(const char *, ...));
#else /* !AWRTC_MBEDTLS_PLATFORM_PRINTF_ALT */
#undef awrtc_mbedtls_printf
#if defined(AWRTC_MBEDTLS_PLATFORM_PRINTF_MACRO)
#define awrtc_mbedtls_printf     AWRTC_MBEDTLS_PLATFORM_PRINTF_MACRO
#else
#define awrtc_mbedtls_printf     printf
#endif /* AWRTC_MBEDTLS_PLATFORM_PRINTF_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_PRINTF_ALT */

/*
 * The function pointers for snprintf
 *
 * The snprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_SNPRINTF)
/* For Windows (inc. MSYS2), we provide our own fixed implementation */
int awrtc_mbedtls_platform_win32_snprintf(char *s, size_t n, const char *fmt, ...);
#endif

#if defined(AWRTC_MBEDTLS_PLATFORM_SNPRINTF_ALT)
extern int (*awrtc_mbedtls_snprintf)(char *s, size_t n, const char *format, ...);

/**
 * \brief                 This function allows configuring a custom
 *                        \c snprintf function pointer.
 *
 * \param snprintf_func   The \c snprintf function implementation.
 *
 * \return                \c 0 on success.
 */
int awrtc_mbedtls_platform_set_snprintf(int (*snprintf_func)(char *s, size_t n,
                                                       const char *format, ...));
#else /* AWRTC_MBEDTLS_PLATFORM_SNPRINTF_ALT */
#undef awrtc_mbedtls_snprintf
#if defined(AWRTC_MBEDTLS_PLATFORM_SNPRINTF_MACRO)
#define awrtc_mbedtls_snprintf   AWRTC_MBEDTLS_PLATFORM_SNPRINTF_MACRO
#else
#define awrtc_mbedtls_snprintf   AWRTC_MBEDTLS_PLATFORM_STD_SNPRINTF
#endif /* AWRTC_MBEDTLS_PLATFORM_SNPRINTF_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_SNPRINTF_ALT */

/*
 * The function pointers for vsnprintf
 *
 * The vsnprintf implementation should conform to C99:
 * - it *must* always correctly zero-terminate the buffer
 *   (except when n == 0, then it must leave the buffer untouched)
 * - however it is acceptable to return -1 instead of the required length when
 *   the destination buffer is too short.
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_HAS_NON_CONFORMING_VSNPRINTF)
#include <stdarg.h>
/* For Older Windows (inc. MSYS2), we provide our own fixed implementation */
int awrtc_mbedtls_platform_win32_vsnprintf(char *s, size_t n, const char *fmt, va_list arg);
#endif

#if defined(AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_ALT)
#include <stdarg.h>
extern int (*awrtc_mbedtls_vsnprintf)(char *s, size_t n, const char *format, va_list arg);

/**
 * \brief   Set your own snprintf function pointer
 *
 * \param   vsnprintf_func   The \c vsnprintf function implementation
 *
 * \return  \c 0
 */
int awrtc_mbedtls_platform_set_vsnprintf(int (*vsnprintf_func)(char *s, size_t n,
                                                         const char *format, va_list arg));
#else /* AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_ALT */
#undef awrtc_mbedtls_vsnprintf
#if defined(AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_MACRO)
#define awrtc_mbedtls_vsnprintf   AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_MACRO
#else
#define awrtc_mbedtls_vsnprintf   vsnprintf
#endif /* AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_VSNPRINTF_ALT */

/*
 * The function pointers for setbuf
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_SETBUF_ALT)
#include <stdio.h>
/**
 * \brief                  Function pointer to call for `setbuf()` functionality
 *                         (changing the internal buffering on stdio calls).
 *
 * \note                   The library calls this function to disable
 *                         buffering when reading or writing sensitive data,
 *                         to avoid having extra copies of sensitive data
 *                         remaining in stdio buffers after the file is
 *                         closed. If this is not a concern, for example if
 *                         your platform's stdio doesn't have any buffering,
 *                         you can set awrtc_mbedtls_setbuf to a function that
 *                         does nothing.
 *
 *                         The library always calls this function with
 *                         `buf` equal to `NULL`.
 */
extern void (*awrtc_mbedtls_setbuf)(FILE *stream, char *buf);

/**
 * \brief                  Dynamically configure the function that is called
 *                         when the awrtc_mbedtls_setbuf() function is called by the
 *                         library.
 *
 * \param   setbuf_func   The \c setbuf function implementation
 *
 * \return                 \c 0
 */
int awrtc_mbedtls_platform_set_setbuf(void (*setbuf_func)(
                                    FILE *stream, char *buf));
#else
#undef awrtc_mbedtls_setbuf
#if defined(AWRTC_MBEDTLS_PLATFORM_SETBUF_MACRO)
/**
 * \brief                  Macro defining the function for the library to
 *                         call for `setbuf` functionality (changing the
 *                         internal buffering on stdio calls).
 *
 * \note                   See extra comments on the awrtc_mbedtls_setbuf() function
 *                         pointer above.
 *
 * \return                 \c 0 on success, negative on error.
 */
#define awrtc_mbedtls_setbuf    AWRTC_MBEDTLS_PLATFORM_SETBUF_MACRO
#else
#define awrtc_mbedtls_setbuf    setbuf
#endif /* AWRTC_MBEDTLS_PLATFORM_SETBUF_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_SETBUF_ALT */

/*
 * The function pointers for exit
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_EXIT_ALT)
extern void (*awrtc_mbedtls_exit)(int status);

/**
 * \brief             This function dynamically configures the exit
 *                    function that is called when the awrtc_mbedtls_exit()
 *                    function is invoked by the library.
 *
 * \param exit_func   The \c exit function implementation.
 *
 * \return            \c 0 on success.
 */
int awrtc_mbedtls_platform_set_exit(void (*exit_func)(int status));
#else
#undef awrtc_mbedtls_exit
#if defined(AWRTC_MBEDTLS_PLATFORM_EXIT_MACRO)
#define awrtc_mbedtls_exit   AWRTC_MBEDTLS_PLATFORM_EXIT_MACRO
#else
#define awrtc_mbedtls_exit   exit
#endif /* AWRTC_MBEDTLS_PLATFORM_EXIT_MACRO */
#endif /* AWRTC_MBEDTLS_PLATFORM_EXIT_ALT */

/*
 * The default exit values
 */
#if defined(AWRTC_MBEDTLS_PLATFORM_STD_EXIT_SUCCESS)
#define AWRTC_MBEDTLS_EXIT_SUCCESS AWRTC_MBEDTLS_PLATFORM_STD_EXIT_SUCCESS
#else
#define AWRTC_MBEDTLS_EXIT_SUCCESS 0
#endif
#if defined(AWRTC_MBEDTLS_PLATFORM_STD_EXIT_FAILURE)
#define AWRTC_MBEDTLS_EXIT_FAILURE AWRTC_MBEDTLS_PLATFORM_STD_EXIT_FAILURE
#else
#define AWRTC_MBEDTLS_EXIT_FAILURE 1
#endif

#if defined(AWRTC_MBEDTLS_ENTROPY_C) && \
    !defined(AWRTC_MBEDTLS_NO_PLATFORM_ENTROPY) && \
    !(defined(_WIN32) && !defined(EFIX64) && !defined(EFI32))
/* Platforms where AWRTC_MBEDTLS_PLATFORM_DEV_RANDOM is used
 * unless a dedicated system call is available both at
 * compile time and at run time. */
#define AWRTC_MBEDTLS_PLATFORM_HAVE_DEV_RANDOM
#endif

#if !defined(AWRTC_MBEDTLS_PLATFORM_DEV_RANDOM)
#define AWRTC_MBEDTLS_PLATFORM_DEV_RANDOM "/dev/random"
#endif

/* Arrange for awrtc_mbedtls_platform_dev_random to always be visible to
 * Doxygen, because it's linked from the documentation of
 * AWRTC_MBEDTLS_PLATFORM_DEV_RANDOM and that documentation can be visible
 * even in configurations where it isn't used. */
#if defined(AWRTC_MBEDTLS_PLATFORM_HAVE_DEV_RANDOM) || defined(__DOXYGEN__)
/**
 * Path to a special file that returns cryptographic-quality random bytes
 * when read.
 *
 * This variable is only declared on platforms where it is used.
 * It is available when the macro `AWRTC_MBEDTLS_PLATFORM_HAVE_DEV_RANDOM` is defined.
 *
 * The default value is #AWRTC_MBEDTLS_PLATFORM_DEV_RANDOM.
 * See the documentation of this option for guidance.
 */
extern const char *awrtc_mbedtls_platform_dev_random;
#endif

/*
 * The function pointers for reading from and writing a seed file to
 * Non-Volatile storage (NV) in a platform-independent way
 *
 * Only enabled when the NV seed entropy source is enabled
 */
#if defined(AWRTC_MBEDTLS_ENTROPY_NV_SEED)
#if !defined(AWRTC_MBEDTLS_PLATFORM_NO_STD_FUNCTIONS) && defined(AWRTC_MBEDTLS_FS_IO)
/* Internal standard platform definitions */
int awrtc_mbedtls_platform_std_nv_seed_read(unsigned char *buf, size_t buf_len);
int awrtc_mbedtls_platform_std_nv_seed_write(unsigned char *buf, size_t buf_len);
#endif

#if defined(AWRTC_MBEDTLS_PLATFORM_NV_SEED_ALT)
extern int (*awrtc_mbedtls_nv_seed_read)(unsigned char *buf, size_t buf_len);
extern int (*awrtc_mbedtls_nv_seed_write)(unsigned char *buf, size_t buf_len);

/**
 * \brief   This function allows configuring custom seed file writing and
 *          reading functions.
 *
 * \param   nv_seed_read_func   The seed reading function implementation.
 * \param   nv_seed_write_func  The seed writing function implementation.
 *
 * \return  \c 0 on success.
 */
int awrtc_mbedtls_platform_set_nv_seed(
    int (*nv_seed_read_func)(unsigned char *buf, size_t buf_len),
    int (*nv_seed_write_func)(unsigned char *buf, size_t buf_len)
    );
#else
#undef awrtc_mbedtls_nv_seed_read
#undef awrtc_mbedtls_nv_seed_write
#if defined(AWRTC_MBEDTLS_PLATFORM_NV_SEED_READ_MACRO) && \
    defined(AWRTC_MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO)
#define awrtc_mbedtls_nv_seed_read    AWRTC_MBEDTLS_PLATFORM_NV_SEED_READ_MACRO
#define awrtc_mbedtls_nv_seed_write   AWRTC_MBEDTLS_PLATFORM_NV_SEED_WRITE_MACRO
#else
#define awrtc_mbedtls_nv_seed_read    awrtc_mbedtls_platform_std_nv_seed_read
#define awrtc_mbedtls_nv_seed_write   awrtc_mbedtls_platform_std_nv_seed_write
#endif
#endif /* AWRTC_MBEDTLS_PLATFORM_NV_SEED_ALT */
#endif /* AWRTC_MBEDTLS_ENTROPY_NV_SEED */

#if !defined(AWRTC_MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT)

/**
 * \brief   The platform context structure.
 *
 * \note    This structure may be used to assist platform-specific
 *          setup or teardown operations.
 */
typedef struct awrtc_mbedtls_platform_context {
    char AWRTC_MBEDTLS_PRIVATE(dummy); /**< A placeholder member, as empty structs are not portable. */
}
awrtc_mbedtls_platform_context;

#else
#include "platform_alt.h"
#endif /* !AWRTC_MBEDTLS_PLATFORM_SETUP_TEARDOWN_ALT */

/**
 * \brief   This function performs any platform-specific initialization
 *          operations.
 *
 * \note    This function should be called before any other library functions.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 * \return  \c 0 on success.
 */
int awrtc_mbedtls_platform_setup(awrtc_mbedtls_platform_context *ctx);
/**
 * \brief   This function performs any platform teardown operations.
 *
 * \note    This function should be called after every other Mbed TLS module
 *          has been correctly freed using the appropriate free function.
 *
 *          Its implementation is platform-specific, and unless
 *          platform-specific code is provided, it does nothing.
 *
 * \note    The usage and necessity of this function is dependent on the platform.
 *
 * \param   ctx     The platform context.
 *
 */
void awrtc_mbedtls_platform_teardown(awrtc_mbedtls_platform_context *ctx);

#ifdef __cplusplus
}
#endif

#endif /* platform.h */
