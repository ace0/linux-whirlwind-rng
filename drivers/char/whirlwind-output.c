/*
 * whirlwind-output.h -- Whirlwind is a secure random number generator.  
 * This file contains routines for securely generating random output values from 
 * the RNG seed values.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 */
#include <linux/random.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include "whirlwind.h"
#include "whirlwind-internal.h"

/* Hash chains for the slow and fast seeds are domains 1 and 2, respectively.
   Output hash is domain 3.*/
#define OUTPUT_HASH_DOMAIN 3

/**
 * Reserves a sequence of unique counter values of the specified @length for use 
 * in generating RNG output values using counter-mode hashing.
 */
static inline __u64
get_rng_output_counter(const unsigned int length)
{
  static atomic64_t rng_output_counter = ATOMIC64_INIT(0);

  /* Reserve a sequence of counter values of the specified length.*/
  __u64 end = atomic_long_add_return(length, &rng_output_counter);

  /* Return the starting point of the sequence.*/
  return end - length;
}

/**
 * Generates an arbitrary @length RNG output (specified in bytes) using the 
 * current seed values of the RNG and computing input blocks by running the seeds 
 * (and a few other values) through a full hash function in counter-mode.
 */
int
ww_generate_bytes(u8* kernel_buffer, u8* __user user_buffer, const unsigned int length)
{
  static const u8 feedbackInput[INPUT_BYTES] = { 0 };
  int i = 0, rv = 0;
  unsigned long flags;

  /* Initial our counter mode input to the hash.*/
  struct counter_mode_input input =
  {
    /* Reserve a sequence of counter values, and initialize our counter value
       to the first in the sequence.*/
    .counter = get_rng_output_counter(length/HASH_BLOCKSIZE + 1),
    .domain  = OUTPUT_HASH_DOMAIN,
    .value1  = get_cycle_counter(),
    .value2  = current->pid,
    .value3  = smp_processor_id(),
  };

  /* Fill the remaining space in the input with HW random, if available.*/
  for (i=0; i < INPUT_TRAILING_WORDS; ++i)
  {
    arch_get_random_long((unsigned long*)(&input.value[i]));
  }

  /* Ensure that the RNG whas been properly initialized before generating any
     output values. */
  ww_initialize();

  /* Grab the lock on the fast seed, and copy it unto the stack.
     We hash the fast seed _after_ we copy it to prevent recovery of the
     fast seed value used to generate this output.  This ensures perfect forward 
     secrecy under the assumption that the our copy on the stack isn't compromised. */
  spin_lock_irqsave(&seed_fast.lock, flags);
  {
    memcpy(input.seed1, seed_fast.seed, SEED_BYTES);
    hash_input(seed_fast.seed, feedbackInput);
  }
  spin_unlock_irqrestore(&seed_fast.lock, flags);

  /* Atomically grab the slow seed and copy it unto the stack as well. */
  spin_lock_irqsave(&seed_slow.lock, flags);
  {
    memcpy(input.seed2, seed_slow.seed, SEED_BYTES);
  }
  spin_unlock_irqrestore(&seed_slow.lock, flags);

  /* After the seed has been copied, we add two inputs to the RNG (that won't  
     be included in this output).  These feedbacks provide some resistance to   
     checkpointing attacks when an attacker tries to sample very frequently from  
     the RNG.*/
  rng_input();

  /* Generate an output value.*/
  rv = hash_output(kernel_buffer, user_buffer, length, &input);

  /* Zero-out sensitive memory.*/
  zmem(&input);

  /* Add our second input to the RNG.*/
  rng_input();
  return rv;
}


