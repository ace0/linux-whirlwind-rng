/*
 * whirlwind-rng-internal.h -- Whirlwind is a secure random number generator.  
 * This file contains routines and  common datatypes for internal use.  
 * For the "public" interface to the Whirlwind RNG, see: whirwind.h.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 */
#ifndef _WW_RNG_INTERNAL
#define _WW_RNG_INTERNAL

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

/* Use SHA512 as our cryptographic hash primitive. */
#define SEED_BYTES      SHA512_DIGEST_SIZE
#define INPUT_BYTES     SHA512_BLOCK_SIZE

/* Zero-out sensitive memory. */
#define zmem(var) memset(var, 0, sizeof(var))

/**
 * Retrieves the current cycle counter, if available, otherwise grabs the kernel 
 * timer (jiffies).
 */
static inline u64
get_cycle_counter(void)
{
  cycles_t cycles = get_cycles();
  return (cycles) ? cycles : jiffies;
}

/**
 * INPUT_TRAILING_WORDS is the number of 64-byte words that rounds out the counter 
 * mode input structure to an even multiple of our hash input size.
 */
#define INPUT_PREFIX_BYTES   ((2*SEED_BYTES)+5*8)
#define INPUT_TRAILING_BYTES (INPUT_PREFIX_BYTES % INPUT_BYTES)
#define INPUT_TRAILING_WORDS (INPUT_TRAILING_BYTES/8)

/**
 * Input message used to create output values in PRNG-counter-mode.
 */
struct counter_mode_input
{
  u64 domain;            /* Unique domain specifier per-use of hash function.*/
                         /* (to ensure domain separation among hashes)*/
  u8 seed1[SEED_BYTES];  /* Dueling seed values.*/
  u8 seed2[SEED_BYTES];  
  u64 counter;           /* Starting counter value for this particular seed.*/
  u64 value1;            /* + 192-bits of caller-provided data.*/
  u64 value2;            /* And a block of words that rounds this structure*/
  u64 value3;            /* to an event multiple of the input block size.*/
  u64 value[INPUT_TRAILING_WORDS];
};

struct seed_info
{
  /* Current (public) seed value for output generation.*/
  u8 seed[SEED_BYTES];

  /* An internal seed value hidden from output generation.  Only used if  
     min_hashes > 1.*/
  u8 __seed_internal[SEED_BYTES];

  /* The number of times the internal seed has been hashed. */
  unsigned int hash_count;

  /* The minimum number of times the internal seed must be hashed before making
     the seed "public". */
  const unsigned int min_hashes;

  /* Write lock for this seed.*/
  spinlock_t lock;
};

/* Shared values between inputs and output routines. */
extern struct seed_info seed_fast;
extern struct seed_info seed_slow;

void ww_initialize(void);

/* Hash function primitives */
void hash_input(u8 seed[SEED_BYTES], const u8 input[INPUT_BYTES]);
int hash_output(u8* kernel_buffer, u8* __user user_buffer, const unsigned int length,
	    struct counter_mode_input* input);

#endif /* _WW_RNG_INTERNAL*/
