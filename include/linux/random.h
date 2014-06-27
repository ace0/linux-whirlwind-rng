/*
 * include/linux/random.h
 *
 * Include file for the random number generator.
 */
#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <uapi/linux/random.h>

/*
extern void add_device_randomness(const void *, unsigned int);
extern void add_input_randomness(unsigned int type, unsigned int code,
				 unsigned int value);
extern void add_interrupt_randomness(int irq, int irq_flags);

extern void get_random_bytes(void *buf, int nbytes);
extern void get_random_bytes_arch(void *buf, int nbytes);
void generate_random_uuid(unsigned char uuid_out[16]);
*/

/**
 * The simplest way to add inputs to the RNG.
 */
#define rng_input() rng_input64(__COUNTER__, __COUNTER__)

/**
 * Add an input to the RNG along with 32-bits of additional (arbitrary) information.
 */
#define rng_input32(value) rng_input64(value, __COUNTER__)

/**
 * Add an input to the RNG along with 2x 32-bit values.
 */
#define rng_input64(value1, value2) ww_add_input(__COUNTER__, value1, value2)

/**
 * Adds an input to the RNG along with a buffer of arbitrary bytes.
 */
#define rng_input_buffer(buffer, length) \
  ww_add_input_buffer(__COUNTER__, buffer, length)

/**
 * Exported functions.
 */

void get_random_bytes(void* buffer, const int length);
unsigned long get_random_ulong(void);
void generate_random_uuid(unsigned char uuid_out[16]);
unsigned long randomize_range(const unsigned long start, const unsigned long end,
                              const unsigned long len);
void ww_add_input(const u32 source_id, const u32 value1, const u32 value2);
void ww_add_input_buffer(const u32 source_id, const void* buffer, const int length);

/**
 * Legacy  interfaces that have been disabled or redirected to common
 * interfaces  These are re-directed for backwards-compatibility.  Future versions 
 * could remove these interfaces and replace them with the standard interfaces above.
 */

 static inline void add_device_randomness(const void* buffer, const int length)
{
  rng_input_buffer(buffer, length);
}

static inline void add_input_randomness(const unsigned int type, 
					const unsigned int code,
                                        const unsigned int value)
{
  rng_input64((u32)type << 16 | code, (u32)value);
}

static inline void add_interrupt_randomness(const int irq, const int irq_flags)
{
  rng_input64(irq, irq_flags);
}

static inline void rand_initialize_irq(const int irq) {}

static inline void get_random_bytes_arch(void* buffer, const int length)
{
  get_random_bytes(buffer, length);
}

static inline unsigned int get_random_int(void)
{
  return (unsigned int)get_random_ulong();
}

#ifndef MODULE
extern const struct file_operations random_fops, urandom_fops;
#endif

unsigned int get_random_int(void);
unsigned long randomize_range(unsigned long start, unsigned long end, unsigned long len);

u32 prandom_u32(void);
void prandom_bytes(void *buf, int nbytes);
void prandom_seed(u32 seed);
void prandom_reseed_late(void);

struct rnd_state {
	__u32 s1, s2, s3, s4;
};

u32 prandom_u32_state(struct rnd_state *state);
void prandom_bytes_state(struct rnd_state *state, void *buf, int nbytes);

/**
 * prandom_u32_max - returns a pseudo-random number in interval [0, ep_ro)
 * @ep_ro: right open interval endpoint
 *
 * Returns a pseudo-random number that is in interval [0, ep_ro). Note
 * that the result depends on PRNG being well distributed in [0, ~0U]
 * u32 space. Here we use maximally equidistributed combined Tausworthe
 * generator, that is, prandom_u32(). This is useful when requesting a
 * random index of an array containing ep_ro elements, for example.
 *
 * Returns: pseudo-random number in interval [0, ep_ro)
 */
static inline u32 prandom_u32_max(u32 ep_ro)
{
	return (u32)(((u64) prandom_u32() * ep_ro) >> 32);
}

/*
 * Handle minimum values for seeds
 */
static inline u32 __seed(u32 x, u32 m)
{
	return (x < m) ? x + m : x;
}

/**
 * prandom_seed_state - set seed for prandom_u32_state().
 * @state: pointer to state structure to receive the seed.
 * @seed: arbitrary 64-bit value to use as a seed.
 */
static inline void prandom_seed_state(struct rnd_state *state, u64 seed)
{
	u32 i = (seed >> 32) ^ (seed << 10) ^ seed;

	state->s1 = __seed(i,   2U);
	state->s2 = __seed(i,   8U);
	state->s3 = __seed(i,  16U);
	state->s4 = __seed(i, 128U);
}

#ifdef CONFIG_ARCH_RANDOM
# include <asm/archrandom.h>
#else
static inline int arch_get_random_long(unsigned long *v)
{
	return 0;
}
static inline int arch_get_random_int(unsigned int *v)
{
	return 0;
}
static inline int arch_has_random(void)
{
	return 0;
}
static inline int arch_get_random_seed_long(unsigned long *v)
{
	return 0;
}
static inline int arch_get_random_seed_int(unsigned int *v)
{
	return 0;
}
static inline int arch_has_random_seed(void)
{
	return 0;
}
#endif

/* Pseudo random number generator from numerical recipes. */
static inline u32 next_pseudo_random32(u32 seed)
{
	return seed * 1664525 + 1013904223;
}

#endif /* _LINUX_RANDOM_H */
