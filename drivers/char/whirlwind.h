/*
 * whirlwind.h -- A secure random number generator
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 */
#ifndef _WW_RNG
#define _WW_RNG

#include <crypto/hash.h>

#define HASH_BLOCKSIZE      SHA512_DIGEST_SIZE

void ww_add_input_buffer(const u32 source_id, const void* buffer, const int length);
void ww_add_input(const u32 source_id, const u32 value1, const u32 value2);
int ww_generate_bytes(u8* kernel_buffer, u8* __user user_buffer, 
		      const unsigned int length);

#endif /* _WW_RNG*/
