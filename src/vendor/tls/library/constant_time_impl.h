/**
 *  Constant-time functions
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef AWRTC_MBEDTLS_CONSTANT_TIME_IMPL_H
#define AWRTC_MBEDTLS_CONSTANT_TIME_IMPL_H

#include <stddef.h>

#include "common.h"

#if defined(AWRTC_MBEDTLS_BIGNUM_C)
#include "../include/mbedtls/bignum.h"
#endif

/*
 * To improve readability of constant_time_internal.h, the static inline
 * definitions are here, and constant_time_internal.h has only the declarations.
 *
 * This results in duplicate declarations of the form:
 *     static inline void f();         // from constant_time_internal.h
 *     static inline void f() { ... }  // from constant_time_impl.h
 * when constant_time_internal.h is included.
 *
 * This appears to behave as if the declaration-without-definition was not present
 * (except for warnings if gcc -Wredundant-decls or similar is used).
 *
 * Disable -Wredundant-decls so that gcc does not warn about this. This is re-enabled
 * at the bottom of this file.
 */
#if defined(AWRTC_MBEDTLS_COMPILER_IS_GCC) && (__GNUC__ > 4)
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wredundant-decls"
#endif

/* armcc5 --gnu defines __GNUC__ but doesn't support GNU's extended asm */
#if defined(AWRTC_MBEDTLS_HAVE_ASM) && defined(__GNUC__) && (!defined(__ARMCC_VERSION) || \
    __ARMCC_VERSION >= 6000000)
#define AWRTC_MBEDTLS_CT_ASM
#if (defined(__arm__) || defined(__thumb__) || defined(__thumb2__))
#define AWRTC_MBEDTLS_CT_ARM_ASM
#elif defined(__aarch64__)
#define AWRTC_MBEDTLS_CT_AARCH64_ASM
#elif defined(__amd64__) || defined(__x86_64__)
#define AWRTC_MBEDTLS_CT_X86_64_ASM
#elif defined(__i386__)
#define AWRTC_MBEDTLS_CT_X86_ASM
#endif
#endif

#define AWRTC_MBEDTLS_CT_SIZE (sizeof(awrtc_mbedtls_ct_uint_t) * 8)


/* ============================================================================
 * Core const-time primitives
 */

/* Ensure that the compiler cannot know the value of x (i.e., cannot optimise
 * based on its value) after this function is called.
 *
 * If we are not using assembly, this will be fairly inefficient, so its use
 * should be minimised.
 */

#if !defined(AWRTC_MBEDTLS_CT_ASM)
extern volatile awrtc_mbedtls_ct_uint_t awrtc_mbedtls_ct_zero;
#endif

/**
 * \brief   Ensure that a value cannot be known at compile time.
 *
 * \param x        The value to hide from the compiler.
 * \return         The same value that was passed in, such that the compiler
 *                 cannot prove its value (even for calls of the form
 *                 x = awrtc_mbedtls_ct_compiler_opaque(1), x will be unknown).
 *
 * \note           This is mainly used in constructing awrtc_mbedtls_ct_condition_t
 *                 values and performing operations over them, to ensure that
 *                 there is no way for the compiler to ever know anything about
 *                 the value of an awrtc_mbedtls_ct_condition_t.
 */
static inline awrtc_mbedtls_ct_uint_t awrtc_mbedtls_ct_compiler_opaque(awrtc_mbedtls_ct_uint_t x)
{
#if defined(AWRTC_MBEDTLS_CT_ASM)
    asm volatile ("" : [x] "+r" (x) :);
    return x;
#else
    return x ^ awrtc_mbedtls_ct_zero;
#endif
}

/*
 * Selecting unified syntax is needed for gcc, and harmless on clang.
 *
 * This is needed because on Thumb 1, condition flags are always set, so
 * e.g. "negs" is supported but "neg" is not (on Thumb 2, both exist).
 *
 * Under Thumb 1 unified syntax, only the "negs" form is accepted, and
 * under divided syntax, only the "neg" form is accepted. clang only
 * supports unified syntax.
 *
 * On Thumb 2 and Arm, both compilers are happy with the "s" suffix,
 * although we don't actually care about setting the flags.
 *
 * For old versions of gcc (see #8516 for details), restore divided
 * syntax afterwards - otherwise old versions of gcc seem to apply
 * unified syntax globally, which breaks other asm code.
 */
#if defined(AWRTC_MBEDTLS_COMPILER_IS_GCC) && defined(__thumb__) && !defined(__thumb2__) && \
    (__GNUC__ < 11) && !defined(__ARM_ARCH_2__)
#define RESTORE_ASM_SYNTAX  ".syntax divided                      \n\t"
#else
#define RESTORE_ASM_SYNTAX
#endif

/* Convert a number into a condition in constant time. */
static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool(awrtc_mbedtls_ct_uint_t x)
{
    /*
     * Define mask-generation code that, as far as possible, will not use branches or conditional instructions.
     *
     * For some platforms / type sizes, we define assembly to assure this.
     *
     * Otherwise, we define a plain C fallback which (in May 2023) does not get optimised into
     * conditional instructions or branches by trunk clang, gcc, or MSVC v19.
     */
#if defined(AWRTC_MBEDTLS_CT_AARCH64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    awrtc_mbedtls_ct_uint_t s;
    asm volatile ("neg %x[s], %x[x]                               \n\t"
                  "orr %x[x], %x[s], %x[x]                        \n\t"
                  "asr %x[x], %x[x], 63                           \n\t"
                  :
                  [s] "=&r" (s),
                  [x] "+&r" (x)
                  :
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#elif defined(AWRTC_MBEDTLS_CT_ARM_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile (".syntax unified                                \n\t"
                  "negs %[s], %[x]                                \n\t"
                  "orrs %[x], %[x], %[s]                          \n\t"
                  "asrs %[x], %[x], #31                           \n\t"
                  RESTORE_ASM_SYNTAX
                  :
                  [s] "=&l" (s),
                  [x] "+&l" (x)
                  :
                  :
                  "cc" /* clobbers flag bits */
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#elif defined(AWRTC_MBEDTLS_CT_X86_64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    uint64_t s;
    asm volatile ("mov  %[x], %[s]                                \n\t"
                  "neg  %[s]                                      \n\t"
                  "or   %[x], %[s]                                \n\t"
                  "sar  $63, %[s]                                 \n\t"
                  :
                  [s] "=&a" (s)
                  :
                  [x] "D" (x)
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) s;
#elif defined(AWRTC_MBEDTLS_CT_X86_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "neg %[s]                                       \n\t"
                  "or %[s], %[x]                                  \n\t"
                  "sar $31, %[x]                                  \n\t"
                  :
                  [s] "=&c" (s),
                  [x] "+&a" (x)
                  :
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#else
    const awrtc_mbedtls_ct_uint_t xo = awrtc_mbedtls_ct_compiler_opaque(x);
#if defined(_MSC_VER)
    /* MSVC has a warning about unary minus on unsigned, but this is
     * well-defined and precisely what we want to do here */
#pragma warning( push )
#pragma warning( disable : 4146 )
#endif
    // y is negative (i.e., top bit set) iff x is non-zero
    awrtc_mbedtls_ct_int_t y = (-xo) | -(xo >> 1);

    // extract only the sign bit of y so that y == 1 (if x is non-zero) or 0 (if x is zero)
    y = (((awrtc_mbedtls_ct_uint_t) y) >> (AWRTC_MBEDTLS_CT_SIZE - 1));

    // -y has all bits set (if x is non-zero), or all bits clear (if x is zero)
    return (awrtc_mbedtls_ct_condition_t) (-y);
#if defined(_MSC_VER)
#pragma warning( pop )
#endif
#endif
}

static inline awrtc_mbedtls_ct_uint_t awrtc_mbedtls_ct_if(awrtc_mbedtls_ct_condition_t condition,
                                              awrtc_mbedtls_ct_uint_t if1,
                                              awrtc_mbedtls_ct_uint_t if0)
{
#if defined(AWRTC_MBEDTLS_CT_AARCH64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    asm volatile ("and %x[if1], %x[if1], %x[condition]            \n\t"
                  "mvn %x[condition], %x[condition]               \n\t"
                  "and %x[condition], %x[condition], %x[if0]      \n\t"
                  "orr %x[condition], %x[if1], %x[condition]"
                  :
                  [condition] "+&r" (condition),
                  [if1] "+&r" (if1)
                  :
                  [if0] "r" (if0)
                  :
                  );
    return (awrtc_mbedtls_ct_uint_t) condition;
#elif defined(AWRTC_MBEDTLS_CT_ARM_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    asm volatile (".syntax unified                                \n\t"
                  "ands %[if1], %[if1], %[condition]              \n\t"
                  "mvns %[condition], %[condition]                \n\t"
                  "ands %[condition], %[condition], %[if0]        \n\t"
                  "orrs %[condition], %[if1], %[condition]        \n\t"
                  RESTORE_ASM_SYNTAX
                  :
                  [condition] "+&l" (condition),
                  [if1] "+&l" (if1)
                  :
                  [if0] "l" (if0)
                  :
                  "cc"
                  );
    return (awrtc_mbedtls_ct_uint_t) condition;
#elif defined(AWRTC_MBEDTLS_CT_X86_64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    asm volatile ("and  %[condition], %[if1]                      \n\t"
                  "not  %[condition]                              \n\t"
                  "and  %[condition], %[if0]                      \n\t"
                  "or   %[if1], %[if0]                            \n\t"
                  :
                  [condition] "+&D" (condition),
                  [if1] "+&S" (if1),
                  [if0] "+&a" (if0)
                  :
                  :
                  );
    return if0;
#elif defined(AWRTC_MBEDTLS_CT_X86_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    asm volatile ("and %[condition], %[if1]                       \n\t"
                  "not %[condition]                               \n\t"
                  "and %[if0], %[condition]                       \n\t"
                  "or %[condition], %[if1]                        \n\t"
                  :
                  [condition] "+&c" (condition),
                  [if1] "+&a" (if1)
                  :
                  [if0] "b" (if0)
                  :
                  );
    return if1;
#else
    awrtc_mbedtls_ct_condition_t not_cond =
        (awrtc_mbedtls_ct_condition_t) (~awrtc_mbedtls_ct_compiler_opaque(condition));
    return (awrtc_mbedtls_ct_uint_t) ((condition & if1) | (not_cond & if0));
#endif
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_lt(awrtc_mbedtls_ct_uint_t x, awrtc_mbedtls_ct_uint_t y)
{
#if defined(AWRTC_MBEDTLS_CT_AARCH64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    uint64_t s1;
    asm volatile ("eor     %x[s1], %x[y], %x[x]                   \n\t"
                  "sub     %x[x], %x[x], %x[y]                    \n\t"
                  "bic     %x[x], %x[x], %x[s1]                   \n\t"
                  "and     %x[s1], %x[s1], %x[y]                  \n\t"
                  "orr     %x[s1], %x[x], %x[s1]                  \n\t"
                  "asr     %x[x], %x[s1], 63"
                  :
                  [s1] "=&r" (s1),
                  [x] "+&r" (x)
                  :
                  [y] "r" (y)
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#elif defined(AWRTC_MBEDTLS_CT_ARM_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    uint32_t s1;
    asm volatile (
        ".syntax unified                                          \n\t"
#if defined(__thumb__) && !defined(__thumb2__)
        "movs     %[s1], %[x]                                     \n\t"
        "eors     %[s1], %[s1], %[y]                              \n\t"
#else
        "eors     %[s1], %[x], %[y]                               \n\t"
#endif
        "subs    %[x], %[x], %[y]                                 \n\t"
        "bics    %[x], %[x], %[s1]                                \n\t"
        "ands    %[y], %[s1], %[y]                                \n\t"
        "orrs    %[x], %[x], %[y]                                 \n\t"
        "asrs    %[x], %[x], #31                                  \n\t"
        RESTORE_ASM_SYNTAX
        :
        [s1] "=&l" (s1),
        [x] "+&l" (x),
        [y] "+&l" (y)
        :
        :
        "cc"
        );
    return (awrtc_mbedtls_ct_condition_t) x;
#elif defined(AWRTC_MBEDTLS_CT_X86_64_ASM) && (defined(AWRTC_MBEDTLS_CT_SIZE_32) || defined(AWRTC_MBEDTLS_CT_SIZE_64))
    uint64_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "xor %[y], %[s]                                 \n\t"
                  "sub %[y], %[x]                                 \n\t"
                  "and %[s], %[y]                                 \n\t"
                  "not %[s]                                       \n\t"
                  "and %[s], %[x]                                 \n\t"
                  "or %[y], %[x]                                  \n\t"
                  "sar $63, %[x]                                  \n\t"
                  :
                  [s] "=&a" (s),
                  [x] "+&D" (x),
                  [y] "+&S" (y)
                  :
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#elif defined(AWRTC_MBEDTLS_CT_X86_ASM) && defined(AWRTC_MBEDTLS_CT_SIZE_32)
    uint32_t s;
    asm volatile ("mov %[x], %[s]                                 \n\t"
                  "xor %[y], %[s]                                 \n\t"
                  "sub %[y], %[x]                                 \n\t"
                  "and %[s], %[y]                                 \n\t"
                  "not %[s]                                       \n\t"
                  "and %[s], %[x]                                 \n\t"
                  "or  %[y], %[x]                                 \n\t"
                  "sar $31, %[x]                                  \n\t"
                  :
                  [s] "=&b" (s),
                  [x] "+&a" (x),
                  [y] "+&c" (y)
                  :
                  :
                  );
    return (awrtc_mbedtls_ct_condition_t) x;
#else
    /* Ensure that the compiler cannot optimise the following operations over x and y,
     * even if it knows the value of x and y.
     */
    const awrtc_mbedtls_ct_uint_t xo = awrtc_mbedtls_ct_compiler_opaque(x);
    const awrtc_mbedtls_ct_uint_t yo = awrtc_mbedtls_ct_compiler_opaque(y);
    /*
     * Check if the most significant bits (MSB) of the operands are different.
     * cond is true iff the MSBs differ.
     */
    awrtc_mbedtls_ct_condition_t cond = awrtc_mbedtls_ct_bool((xo ^ yo) >> (AWRTC_MBEDTLS_CT_SIZE - 1));

    /*
     * If the MSB are the same then the difference x-y will be negative (and
     * have its MSB set to 1 during conversion to unsigned) if and only if x<y.
     *
     * If the MSB are different, then the operand with the MSB of 1 is the
     * bigger. (That is if y has MSB of 1, then x<y is true and it is false if
     * the MSB of y is 0.)
     */

    // Select either y, or x - y
    awrtc_mbedtls_ct_uint_t ret = awrtc_mbedtls_ct_if(cond, yo, (awrtc_mbedtls_ct_uint_t) (xo - yo));

    // Extract only the MSB of ret
    ret = ret >> (AWRTC_MBEDTLS_CT_SIZE - 1);

    // Convert to a condition (i.e., all bits set iff non-zero)
    return awrtc_mbedtls_ct_bool(ret);
#endif
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_ne(awrtc_mbedtls_ct_uint_t x, awrtc_mbedtls_ct_uint_t y)
{
    /* diff = 0 if x == y, non-zero otherwise */
    const awrtc_mbedtls_ct_uint_t diff = awrtc_mbedtls_ct_compiler_opaque(x) ^ awrtc_mbedtls_ct_compiler_opaque(y);

    /* all ones if x != y, 0 otherwise */
    return awrtc_mbedtls_ct_bool(diff);
}

static inline unsigned char awrtc_mbedtls_ct_uchar_in_range_if(unsigned char low,
                                                         unsigned char high,
                                                         unsigned char c,
                                                         unsigned char t)
{
    const unsigned char co = (unsigned char) awrtc_mbedtls_ct_compiler_opaque(c);
    const unsigned char to = (unsigned char) awrtc_mbedtls_ct_compiler_opaque(t);

    /* low_mask is: 0 if low <= c, 0x...ff if low > c */
    unsigned low_mask = ((unsigned) co - low) >> 8;
    /* high_mask is: 0 if c <= high, 0x...ff if c > high */
    unsigned high_mask = ((unsigned) high - co) >> 8;

    return (unsigned char) (~(low_mask | high_mask)) & to;
}

/* ============================================================================
 * Everything below here is trivial wrapper functions
 */

static inline size_t awrtc_mbedtls_ct_size_if(awrtc_mbedtls_ct_condition_t condition,
                                        size_t if1,
                                        size_t if0)
{
    return (size_t) awrtc_mbedtls_ct_if(condition, (awrtc_mbedtls_ct_uint_t) if1, (awrtc_mbedtls_ct_uint_t) if0);
}

static inline unsigned awrtc_mbedtls_ct_uint_if(awrtc_mbedtls_ct_condition_t condition,
                                          unsigned if1,
                                          unsigned if0)
{
    return (unsigned) awrtc_mbedtls_ct_if(condition, (awrtc_mbedtls_ct_uint_t) if1, (awrtc_mbedtls_ct_uint_t) if0);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_if(awrtc_mbedtls_ct_condition_t condition,
                                                        awrtc_mbedtls_ct_condition_t if1,
                                                        awrtc_mbedtls_ct_condition_t if0)
{
    return (awrtc_mbedtls_ct_condition_t) awrtc_mbedtls_ct_if(condition, (awrtc_mbedtls_ct_uint_t) if1,
                                                  (awrtc_mbedtls_ct_uint_t) if0);
}

#if defined(AWRTC_MBEDTLS_BIGNUM_C)

static inline awrtc_mbedtls_mpi_uint awrtc_mbedtls_ct_mpi_uint_if(awrtc_mbedtls_ct_condition_t condition,
                                                      awrtc_mbedtls_mpi_uint if1,
                                                      awrtc_mbedtls_mpi_uint if0)
{
    return (awrtc_mbedtls_mpi_uint) awrtc_mbedtls_ct_if(condition,
                                            (awrtc_mbedtls_ct_uint_t) if1,
                                            (awrtc_mbedtls_ct_uint_t) if0);
}

#endif

static inline size_t awrtc_mbedtls_ct_size_if_else_0(awrtc_mbedtls_ct_condition_t condition, size_t if1)
{
    return (size_t) (condition & if1);
}

static inline unsigned awrtc_mbedtls_ct_uint_if_else_0(awrtc_mbedtls_ct_condition_t condition, unsigned if1)
{
    return (unsigned) (condition & if1);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_if_else_0(awrtc_mbedtls_ct_condition_t condition,
                                                               awrtc_mbedtls_ct_condition_t if1)
{
    return (awrtc_mbedtls_ct_condition_t) (condition & if1);
}

#if defined(AWRTC_MBEDTLS_BIGNUM_C)

static inline awrtc_mbedtls_mpi_uint awrtc_mbedtls_ct_mpi_uint_if_else_0(awrtc_mbedtls_ct_condition_t condition,
                                                             awrtc_mbedtls_mpi_uint if1)
{
    return (awrtc_mbedtls_mpi_uint) (condition & if1);
}

#endif /* AWRTC_MBEDTLS_BIGNUM_C */

static inline int awrtc_mbedtls_ct_error_if(awrtc_mbedtls_ct_condition_t condition, int if1, int if0)
{
    /* Coverting int -> uint -> int here is safe, because we require if1 and if0 to be
     * in the range -32767..0, and we require 32-bit int and uint types.
     *
     * This means that (0 <= -if0 < INT_MAX), so negating if0 is safe, and similarly for
     * converting back to int.
     */
    return -((int) awrtc_mbedtls_ct_if(condition, (awrtc_mbedtls_ct_uint_t) (-if1),
                                 (awrtc_mbedtls_ct_uint_t) (-if0)));
}

static inline int awrtc_mbedtls_ct_error_if_else_0(awrtc_mbedtls_ct_condition_t condition, int if1)
{
    return -((int) (condition & (-if1)));
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_eq(awrtc_mbedtls_ct_uint_t x,
                                                        awrtc_mbedtls_ct_uint_t y)
{
    return ~awrtc_mbedtls_ct_uint_ne(x, y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_gt(awrtc_mbedtls_ct_uint_t x,
                                                        awrtc_mbedtls_ct_uint_t y)
{
    return awrtc_mbedtls_ct_uint_lt(y, x);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_ge(awrtc_mbedtls_ct_uint_t x,
                                                        awrtc_mbedtls_ct_uint_t y)
{
    return ~awrtc_mbedtls_ct_uint_lt(x, y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_uint_le(awrtc_mbedtls_ct_uint_t x,
                                                        awrtc_mbedtls_ct_uint_t y)
{
    return ~awrtc_mbedtls_ct_uint_gt(x, y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_ne(awrtc_mbedtls_ct_condition_t x,
                                                        awrtc_mbedtls_ct_condition_t y)
{
    return (awrtc_mbedtls_ct_condition_t) (x ^ y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_and(awrtc_mbedtls_ct_condition_t x,
                                                         awrtc_mbedtls_ct_condition_t y)
{
    return (awrtc_mbedtls_ct_condition_t) (x & y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_or(awrtc_mbedtls_ct_condition_t x,
                                                        awrtc_mbedtls_ct_condition_t y)
{
    return (awrtc_mbedtls_ct_condition_t) (x | y);
}

static inline awrtc_mbedtls_ct_condition_t awrtc_mbedtls_ct_bool_not(awrtc_mbedtls_ct_condition_t x)
{
    return (awrtc_mbedtls_ct_condition_t) (~x);
}

#if defined(AWRTC_MBEDTLS_COMPILER_IS_GCC) && (__GNUC__ > 4)
/* Restore warnings for -Wredundant-decls on gcc */
    #pragma GCC diagnostic pop
#endif

#endif /* AWRTC_MBEDTLS_CONSTANT_TIME_IMPL_H */
