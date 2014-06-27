/*
 * whirlwind-input.h -- Whirlwind is a secure random number generator.  
 * This file contains routines for securely extracting randomness from biased inputs.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 */
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/cryptohash.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include <linux/module.h> 
#include "whirlwind.h"
#include "whirlwind-internal.h"

/* The number of hashes before the internal slow seed is made "public" */
#define SLOW_SEED_HASHES 50

/* Establishes how often inputs are diverted to the slow seed. */
#define SLOW_SEED_INPUTS 10

/* Buffer and index for accumulating unhashed inputs to the fast seed. */
DEFINE_PER_CPU(u8[INPUT_BYTES], input_fast);
DEFINE_PER_CPU(unsigned int, write_index_fast);

/* Buffer and index for accumulating unhashed inputs to the slow seed. */
DEFINE_PER_CPU(u8[INPUT_BYTES], input_slow);
DEFINE_PER_CPU(unsigned int, write_index_slow);

/**
 * An input value that can be added the Whirlwind RNG.
 */
struct rng_input
{
  /* Unique value that identifies the source of each input */
  u32 source_id;

  /* Lower 4 bytes of a ycle counter at the time the input sample is contributed. */
  u32 cycles;

  /* 64-bits of source-contributed data.  These can be any values that are expected   
     to be hard to predict or can be left empty if no such values are available.*/
  u32 value1;
  u32 value2;
};

/* The fast seed is really fast -- all hashes are immediately exposed as public. */
struct seed_info seed_fast = 
{
  .hash_count  = 0,
  .min_hashes  = 1,
  .lock        = __SPIN_LOCK_UNLOCKED(&seed_fast.lock),

  /* This is SHA512(IV, 0x0000 0001)
     1 is the hash domain assigned to the fast seed hash chain. */
  .seed =
  { 0xdf, 0x9c, 0x47, 0x8c, 0x05, 0x32, 0x10, 0x87,
    0xb5, 0x0a, 0x1d, 0x23, 0x9b, 0x4a, 0xab, 0x29, 
    0x0e, 0x9b, 0x79, 0x32, 0x52, 0x75, 0x8e, 0x70, 
    0x6e, 0x24, 0x31, 0x2a, 0xed, 0x21, 0xc2, 0x90, 
    0x72, 0x28, 0x5e, 0x43, 0x6a, 0x20, 0xc3, 0xc6, 
    0x22, 0x7f, 0x99, 0xb7, 0x36, 0x38, 0xf0, 0x41, 
    0x4f, 0xba, 0x58, 0x35, 0x58, 0x6f, 0xee, 0x4e, 
    0x19, 0x23, 0x1c, 0x1e, 0xc5, 0x6d, 0x58, 0xee
  }
};

/* Hold back a number of inputs for the slow seed to increase an attacker's
   complexity of predicting all inputs. */
struct seed_info seed_slow = 
{
  .hash_count  = 0,
  .min_hashes  = SLOW_SEED_HASHES,
  .lock        = __SPIN_LOCK_UNLOCKED(&seed_slow.lock),

  /* This is SHA512(IV, 0x0000 0002)
     2 is the hash domain assigned to the slow seed hash chain. */
  .seed =
  {
    0xdf, 0xa8, 0xdb, 0x1c, 0x35, 0x93, 0x19, 0x31, 
    0xa6, 0x00, 0x7f, 0x85, 0xa9, 0xf4, 0x03, 0x59, 
    0x28, 0xcf, 0x15, 0x93, 0x57, 0xff, 0x8d, 0x68, 
    0x2a, 0x50, 0xb6, 0xa0, 0xf3, 0xdf, 0xa0, 0xe0, 
    0x20, 0xed, 0x4e, 0xb3, 0x77, 0xf6, 0x01, 0x14, 
    0x46, 0xf3, 0x51, 0xf7, 0x00, 0x1b, 0xae, 0x06, 
    0x93, 0x2a, 0xd0, 0xcb, 0x66, 0x2e, 0x01, 0xf0, 
    0x7a, 0xcf, 0x6a, 0xee, 0x25, 0x7d, 0x3b, 0xad
  },

  /* Same value as above. */
  .__seed_internal =
  {
    0xdf, 0xa8, 0xdb, 0x1c, 0x35, 0x93, 0x19, 0x31, 
    0xa6, 0x00, 0x7f, 0x85, 0xa9, 0xf4, 0x03, 0x59, 
    0x28, 0xcf, 0x15, 0x93, 0x57, 0xff, 0x8d, 0x68, 
    0x2a, 0x50, 0xb6, 0xa0, 0xf3, 0xdf, 0xa0, 0xe0, 
    0x20, 0xed, 0x4e, 0xb3, 0x77, 0xf6, 0x01, 0x14, 
    0x46, 0xf3, 0x51, 0xf7, 0x00, 0x1b, 0xae, 0x06, 
    0x93, 0x2a, 0xd0, 0xcb, 0x66, 0x2e, 0x01, 0xf0, 
    0x7a, 0xcf, 0x6a, 0xee, 0x25, 0x7d, 0x3b, 0xad
  }
};

/**
 * Copies up to @length bytes from @src to @dest.  Starts copying @src_offset bytes
 * into the source buffer.  The number of bytes copied will not exceed @dest_size, 
 * the number of bytes in the src buffer, or @length.  Returns the number of bytes copied.
 */
static inline int
memcpy_limit(void* dest, const unsigned int dest_size, const void* src, 
	     const unsigned int src_offset, const unsigned int src_size, 
	     const unsigned int length)
{
  /* The number of bytes we intend to copy */
  unsigned int size = 0;

  /* Don't bother if the either pointer is null or if the offset exceeds the size of the 
     source buffer */
  if (likely(src_offset < length && dest != NULL && src != NULL))
  {
    /* Don't exceed the size of either byffer or the number of bytes requested to copy. */
    size = min_t(unsigned int, dest_size, src_size - src_offset);
    size = min_t(unsigned int, size, length);
    memcpy(dest, src + src_offset, size);
  }  

  /* Report how many bytes we copied */
  return size;
}

/** 
 * Hashes the contents of an input buffer into a seed. If the hash count matches 
 * the minimum hash count, then the internal seed value is made "public" - available
 * for output generation.
 */
static void 
hash_input_buffer(const u8 input[INPUT_BYTES], struct seed_info* info)
{
  unsigned long flags;

  /* Grab the lock for each hash. */
  spin_lock_irqsave(&info->lock, flags);

  /* Unless min-hashes is > 1, just hash the input directly into the 
     seed and quit. */
  if (info->min_hashes <= 1)
  {
    /* Hash the input buffer into the seed, release the lock, then quit. */
    hash_input(info->seed, input);
    goto out;
  }

  /* Otherwise, hash into the internal seed and increment the hash counter. */
  hash_input(info->__seed_internal, input);
  info->hash_count += 1;
  
  /* Make the internal seed "public" whenever the minimum number of hashes
     has occurred. */
  if (info->hash_count % info->min_hashes == 0)
  {
    memcpy(info->seed, info->__seed_internal, SEED_BYTES);
  }

out:
  /* Release the hounds/lock. */
  spin_unlock_irqrestore(&info->lock, flags);
}

/**
 * Adds the contents of rng_input to an input buffer associated with the
 * given seed. If the input buffer is full, the contents will hashed into a new seed
 * value.  In the case of the slow seed, if the hash count matches the min-hash count,
 * the internal seed value is made "public".
 */
static void
add_to_seed(const struct rng_input* input, struct seed_info* info)
{
  unsigned int length=0, index = 0, space_available;
  u8* input_buffer = NULL;

  /* The length of the input is not to exceed the size of the buffer. */
  const unsigned int input_length = min_t(unsigned int, sizeof(struct rng_input),
  		INPUT_BYTES);

  /* Basic quality control on the input parameter -- discard null pointers
     or inputs that are identically 0. */
  if (input == 0 || 
      input->source_id + input->cycles + input->value1 + input->value2 == 0)
  {
    return;
  }

  /* Grab the input buffer and the write_index associated with this seed and this CPU. */
  if (info == &seed_fast)
  {
    /* Fast seed */
    index = get_cpu_var(write_index_fast) % INPUT_BYTES;
    input_buffer = get_cpu_var(input_fast);
  }
  else
  {
    /* Slow seed */
    index = get_cpu_var(write_index_slow) % INPUT_BYTES;
    input_buffer = get_cpu_var(input_slow);
  }

  /* Determine the space available in the buffer and the maximum length we can write. */
  space_available = INPUT_BYTES - index;
  length = min_t(unsigned int, space_available, input_length);

  /* Write to the buffer. */
  memcpy(input_buffer + index, input, length);

  /* If the buffer is full, then hash the contents now. */
  if (length >= space_available)
  {
    hash_input_buffer(input_buffer, info);
  }

  /* If we had to truncate our write, wrap around and overwrite
     values from the start of the info.*/
  if (length > space_available)
  {
    memcpy(input_buffer, input + length, input_length - length);
  }
 
  /* Put our per-cpu variables away. */
  if (info == &seed_fast)
  {
    /* Fast seed variables */
    get_cpu_var(write_index_fast) += length;
    put_cpu_var(write_index_fast);
    put_cpu_var(input_fast);
  }
  else
  {
    /* Slow seed variables */
    get_cpu_var(write_index_slow) += length;
    put_cpu_var(write_index_slow);
    put_cpu_var(input_slow);
  }
}

/**
 * Selects the proper input buffer and adds an input to that buffer.
 */
static inline void
select_seed(const struct rng_input* input)
{
  /* The total number of inputs we've added.*/
  static atomic_t input_count = ATOMIC_INIT(0);

  /* Increment the counter, select a seed, and add the input.*/
  unsigned int count = atomic_inc_return(&input_count);
  struct seed_info* info = (count % SLOW_SEED_INPUTS == 0) ? &seed_slow : &seed_fast;
  add_to_seed(input, info);
}

/**
 * Quickly add entropy to an RNG through the use of nested timing loops.
 */
static void 
ww_bootstrap(void)
{
  /* The number of outer loop iterations. */
  const int loops = 100;

  /* The maximum number of inner-loop iterations. */
  const int inner_loop_max = 1024;

  /* Inner and outer loop counters, work variable, and a cycle counter. */
  unsigned int i, j, a=0;

  struct rng_input input =
    {
      .source_id = __COUNTER__,
      .value1    = __COUNTER__,
      .value2    = __COUNTER__
    };
  
  /* Add the specified number of inputs to the rng. */
  for (i = 0; i < loops; ++i) 
  {
    input.cycles = get_cycles();
    select_seed(&input);

    /* Run a variable-length inner loop. */
    for (j = 0; j < (input.cycles % inner_loop_max); ++j) 
    {
      a = (input.cycles/(j+1)) - (a*i) + 1;
    }
  }

  /* Add the result of our work loops to the RNG.  This is cheifly to create a 
     data dependency and ensure that the compiler cannot optimize away any of the
     preceding loops.  The final value itself isn't expected to contribute much,
     if any security to the RNG.  
  */
  rng_input32(a);
}

/**
 * Add a new input to the Whirlwind RNG.
 * @source_id: A unique identifier for this source.  Ideally, use a compile-time
 *             macro like __COUNTER__. Better yet, just use rng_input() macros which 
 *             do this automatically.
 * @value1: 32 bits of source provided data.
 * @value2: 32 more bits of source provided data.
 */
void 
ww_add_input(const u32 source_id, const u32 value1, const u32 value2)
{
  /* Prepare our input, add a cycle counter, and add the input to the RNG. */
  struct rng_input input =
    {
      .source_id = source_id,
      .cycles    = get_cycle_counter(),
      .value1    = value1,
      .value2    = value2
    };
  select_seed(&input);
}
EXPORT_SYMBOL(ww_add_input);

/**
 * Adds a buffer of bytes as input to the Whirlwind RNG.
 */
void 
ww_add_input_buffer(const u32 source_id, const void* buffer, const int length)
{
  unsigned int i = 0;
  struct rng_input input;

  /* Sanity check our parameters */
  if (buffer == NULL || length <= 0)
  {
    return;
  }

  /* Set the source ID */
  input.source_id = source_id;

  /* Continue adding bytes from the buffer until no more input bytes remain */
  while (i < length)
  {
    /* Refresh the cycle counter for each increment. */
    input.cycles = get_cycle_counter();

    /* Copy bytes from the buffer into value1 and value2, but don't exceed
       the size of each field or the number of bytes in the buffer */
    i+= memcpy_limit(&input.value1, sizeof(&input.value1), buffer, i, length, length);
    i+= memcpy_limit(&input.value2, sizeof(&input.value1), buffer, i, length, length);

    /* Add this input to the RNG. */
    select_seed(&input);
  }

  /* Erase our input object */
  zmem(&input);
}
EXPORT_SYMBOL(ww_add_input_buffer);

/**
 * Initializes the Whirlwind RNG prior to its first output.
 */
inline void
ww_initialize(void)
{
  /* Indicates whether the RNG has been initialized after boot. */
  static atomic_t initialized = ATOMIC_INIT(0);
  
  /* Check the flag. */
  if (unlikely(atomic_read(&initialized) == 0))
  {
    /* Initialize the RNG and set the flag. */
    ww_bootstrap();
    atomic_inc(&initialized);
  }
}
