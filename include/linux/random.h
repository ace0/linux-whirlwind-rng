/*
 * include/linux/random.h
 *
 * Interfaces to the Linux random number ggenerators.
 */
#ifndef _LINUX_RANDOM_H
#define _LINUX_RANDOM_H

#include <linux/types.h>
#include <linux/ioctl.h>
#include <linux/irqnr.h>

/**
 * All ioctl's are disabled in the Whirlwind implementation.
 * These definitions remain for backwards *compile time) compatability.
 * Calling any RND ioctl's will generate the error value -EINVAL.
 */
#define RNDGETENTCNT	_IOR( 'R', 0x00, int )
#define RNDADDTOENTCNT	_IOW( 'R', 0x01, int )
#define RNDGETPOOL	_IOR( 'R', 0x02, int [2] )
#define RNDADDENTROPY	_IOW( 'R', 0x03, int [2] )
#define RNDZAPENTCNT	_IO( 'R', 0x04 )
#define RNDCLEARPOOL	_IO( 'R', 0x06 )

struct rand_pool_info {
	int	entropy_count;
	int	buf_size;
	__u32	buf[0];
};

struct rnd_state {
	__u32 s1, s2, s3;
};

#ifdef __KERNEL__
#include <asm/irq.h>
#include <asm/irq_regs.h>

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
 * interfaces  These are re-directed for backwards-compatibility.  Future versions could remove these
 * intefaces and replace them with the standard interfaces above.
 */

static inline void add_device_randomness(const void* buffer, const int length)
{
  rng_input_buffer(buffer, length);
}

static inline void add_input_randomness(const unsigned int type, const unsigned int code, 
					const unsigned int value)
{
  rng_input64((u32)type << 16 | code, (u32)value);  
}

static inline void add_interrupt_randomness(const int irq, const int irq_flags)
{
  sb_add_interrupt_randomness(irq, irq_flags);
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

u32 random32(void);
void srandom32(u32 seed);
u32 prandom32(struct rnd_state *);

/**
 * Handle minimum values for seeds
 */
static inline u32 __seed(u32 x, u32 m)
{
	return (x < m) ? x + m : x;
}

/**
 * prandom32_seed - set seed for prandom32().
 * @state: pointer to state structure to receive the seed.
 * @seed: arbitrary 64-bit value to use as a seed.
 */
static inline void prandom32_seed(struct rnd_state *state, u64 seed)
{
	u32 i = (seed >> 32) ^ (seed << 10) ^ seed;

	state->s1 = __seed(i, 1);
	state->s2 = __seed(i, 7);
	state->s3 = __seed(i, 15);
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
#endif

#endif /* __KERNEL___ */
#endif /* _LINUX_RANDOM_H */
