/*
 * whirlwind--hash.c -- Whirlwind is a secure random number generator.  
 * This file contains SHA-512 hash function primitives used in the Whirlwind RNG.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 * Copyright (c) Jean-Luc Cooke <jlcooke@certainkey.com>
 * Copyright (c) Andrew McDonald <andrew@mcdonald.org.uk>
 * Copyright (c) 2003 Kyle McMartin <kyle@debian.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 */
#include "whirlwind.h"
#include "whirlwind-internal.h"

/*******************************************************************
 *
 * SHA-512 implementation from sha512_generic.c
 *
 *******************************************************************/
static inline u64 Ch(u64 x, u64 y, u64 z)
{
  return z ^ (x & (y ^ z));
}

static inline u64 Maj(u64 x, u64 y, u64 z)
{
  return (x & y) | (z & (x | y));
}

static const u64 sha512_K[80] = 
{
  0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
  0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
  0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
  0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
  0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
  0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
  0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
  0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
  0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
  0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
  0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
  0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
  0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
  0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
  0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
  0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
  0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
  0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
  0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
  0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
  0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
  0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
  0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL,
};

#define e0(x)       (ror64(x,28) ^ ror64(x,34) ^ ror64(x,39))
#define e1(x)       (ror64(x,14) ^ ror64(x,18) ^ ror64(x,41))
#define s0(x)       (ror64(x, 1) ^ ror64(x, 8) ^ (x >> 7))
#define s1(x)       (ror64(x,19) ^ ror64(x,61) ^ (x >> 6))

static inline void LOAD_OP(int I, u64 *W, const u8 *input)
{
  W[I] = __be64_to_cpu( ((__be64*)(input))[I] );
}

static inline void BLEND_OP(int I, u64 *W)
{
  W[I & 15] += s1(W[(I-2) & 15]) + W[(I-7) & 15] + s0(W[(I-15) & 15]);
}

static void
sha512_transform(u64 *state, const u8 *input)
{
  u64 a, b, c, d, e, f, g, h, t1, t2;
  
  int i;
  u64 W[16];
  
  /* load the state into our registers */
  a=state[0];   b=state[1];   c=state[2];   d=state[3];
  e=state[4];   f=state[5];   g=state[6];   h=state[7];
  
  /* now iterate */
  for (i=0; i<80; i+=8) {
    if (!(i & 8)) {
      int j;

      if (i < 16) {
	/* load the input */
	for (j = 0; j < 16; j++)
	  LOAD_OP(i + j, W, input);
      } else {
	for (j = 0; j < 16; j++) {
	  BLEND_OP(i + j, W);
	}
      }
    }
    
    t1 = h + e1(e) + Ch(e,f,g) + sha512_K[i  ] + W[(i & 15)];
    t2 = e0(a) + Maj(a,b,c);    d+=t1;    h=t1+t2;
    t1 = g + e1(d) + Ch(d,e,f) + sha512_K[i+1] + W[(i & 15) + 1];
    t2 = e0(h) + Maj(h,a,b);    c+=t1;    g=t1+t2;
    t1 = f + e1(c) + Ch(c,d,e) + sha512_K[i+2] + W[(i & 15) + 2];
    t2 = e0(g) + Maj(g,h,a);    b+=t1;    f=t1+t2;
    t1 = e + e1(b) + Ch(b,c,d) + sha512_K[i+3] + W[(i & 15) + 3];
    t2 = e0(f) + Maj(f,g,h);    a+=t1;    e=t1+t2;
    t1 = d + e1(a) + Ch(a,b,c) + sha512_K[i+4] + W[(i & 15) + 4];
    t2 = e0(e) + Maj(e,f,g);    h+=t1;    d=t1+t2;
    t1 = c + e1(h) + Ch(h,a,b) + sha512_K[i+5] + W[(i & 15) + 5];
    t2 = e0(d) + Maj(d,e,f);    g+=t1;    c=t1+t2;
    t1 = b + e1(g) + Ch(g,h,a) + sha512_K[i+6] + W[(i & 15) + 6];
    t2 = e0(c) + Maj(c,d,e);    f+=t1;    b=t1+t2;
    t1 = a + e1(f) + Ch(f,g,h) + sha512_K[i+7] + W[(i & 15) + 7];
    t2 = e0(b) + Maj(b,c,d);    e+=t1;    a=t1+t2;
  }
  
  state[0] += a; state[1] += b; state[2] += c; state[3] += d;
  state[4] += e; state[5] += f; state[6] += g; state[7] += h;
  
  /* erase our data */
  a = b = c = d = e = f = g = h = t1 = t2 = 0;
}

static void
sha512_init(struct sha512_state *sctx)
{
  sctx->state[0] = SHA512_H0;
  sctx->state[1] = SHA512_H1;
  sctx->state[2] = SHA512_H2;
  sctx->state[3] = SHA512_H3;
  sctx->state[4] = SHA512_H4;
  sctx->state[5] = SHA512_H5;
  sctx->state[6] = SHA512_H6;
  sctx->state[7] = SHA512_H7;
  sctx->count[0] = sctx->count[1] = 0;
}

static void
sha512_update(struct sha512_state *sctx, const u8 *data, unsigned int len)
{
  unsigned int i, index, part_len;
  
  /* Compute number of bytes mod 128 */
  index = sctx->count[0] & 0x7f;
  
  /* Update number of bytes */
  if ((sctx->count[0] += len) < len)
    sctx->count[1]++;
  
  part_len = 128 - index;
  
  /* Transform as many times as possible. */
  if (len >= part_len) {
    memcpy(&sctx->buf[index], data, part_len);
    sha512_transform(sctx->state, sctx->buf);
    
    for (i = part_len; i + 127 < len; i+=128)
      sha512_transform(sctx->state, &data[i]);
    
    index = 0;
  } else {
    i = 0;
  }
  
  /* Buffer remaining input */
  memcpy(&sctx->buf[index], &data[i], len - i);
}

static void
sha512_final(struct sha512_state *sctx, u8 *hash)
{
  static u8 padding[128] = { 0x80, };
  __be64 *dst = (__be64 *)hash;
  __be64 bits[2];
  unsigned int index, pad_len;
  int i;
  
  /* Save number of bits */
  bits[1] = cpu_to_be64(sctx->count[0] << 3);
  bits[0] = cpu_to_be64(sctx->count[1] << 3 | sctx->count[0] >> 61);
  
  /* Pad out to 112 mod 128. */
  index = sctx->count[0] & 0x7f;
  pad_len = (index < 112) ? (112 - index) : ((128+112) - index);
  sha512_update(sctx, padding, pad_len);
  
  /* Append length (before padding) */
  sha512_update(sctx, (const u8 *)bits, sizeof(bits));
  
  /* Store state in digest */
  for (i = 0; i < 8; i++)
    dst[i] = cpu_to_be64(sctx->state[i]);
  
  /* Zeroize sensitive information. */
  memset(sctx, 0, sizeof(struct sha512_state));
}

/**
 * Perform a full SHA-512 hash over the message provided.
 */
static inline void
sha512_hash(const u8* message, const unsigned int len, u8 digest[HASH_BLOCKSIZE])
{
  struct sha512_state hash;
  sha512_init(&hash);
  sha512_update(&hash, message, len);
  sha512_final(&hash, digest);
}

/*******************************************************************
 *
 * Simplified interface for use in Whirlwind.
 *
 *******************************************************************/

/**
 * Hashes a single block of input back into an existing seed value
 * using just the SHA-512 compression function.
 */
inline void
hash_input(u8 seed[SEED_BYTES], const u8 input[INPUT_BYTES])
{
  sha512_transform((u64*)seed, (u8*)input);
}

/**
 * Generates an output value using (full) SHA-512 in counter mode.  Output value is 
 * placed in either the kernel_buffer or the user_buffer - whichever pointer is 
 * non-null.
 */
int
hash_output(u8* kernel_buffer, u8* __user user_buffer, const unsigned int size,
	    struct counter_mode_input* input)
{
  unsigned int total = 0;       /* Total number of bytes copied to output buffer so far*/
  unsigned int blocksize = 0;   /* The number of bytes copied to the output buffer*/
  u8 block[HASH_BLOCKSIZE];     /* Generate 1-block of output at a time.*/

  /* Ensure that we have at least one valid destination pointer.*/
  if (kernel_buffer == NULL && user_buffer == NULL)
  	return -EFAULT;

  /* Keep generating bytes until we reach the requested size.*/
  while (total < size)
  {
    /* Generate a single block of output.*/
    sha512_hash((u8*)input, sizeof(struct counter_mode_input), block);

    /* Truncate the block if necessary and copy it to the output buffer.*/
    blocksize = min_t(int, HASH_BLOCKSIZE, (size-total));

    /* Select the copy routine based on the type of pointer we were given.*/
    if (kernel_buffer)
    {
    	/* Copy the block to output buffer.*/
    	memcpy(kernel_buffer + total, block, blocksize);
    }
    else
    {
    	/* Copy the block to user space and check for errors.*/
    	if (copy_to_user(user_buffer + total, block, blocksize))
    	{
    		zmem(block);
    		return -EFAULT;
    	}
    }

    /* Account for the bytes we've copied and increment the counter.*/
    total += blocksize;
    input->counter++;
  }

  /* Zero-out our intermediate buffer.*/
  zmem(block);
  return 0;
}
