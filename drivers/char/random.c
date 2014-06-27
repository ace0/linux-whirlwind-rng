/**
 * random.c -- A secure random number generator interface that uses the Whirlwind RNG.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2012.  All rights reserved.
 * Copyright Matt Mackall <mpm@selenic.com>, 2003, 2004, 2005
 * Copyright Theodore Ts'o, 1994, 1995, 1996, 1997, 1998, 1999.  All
 * rights reserved.
*/
#include <linux/fs.h>
#include <linux/random.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/percpu.h>
#include "whirlwind.h"

/**
 * Legacy intefaces re-directed to standard interfaces.
 */
#ifdef CONFIG_BLOCK
void rand_initialize_disk(struct gendisk *disk) {}

#include <linux/genhd.h>
inline void add_disk_randomness(struct gendisk* disk)
{
  rng_input_buffer(disk, sizeof(struct gendisk));
}
#endif

/**
 * Generates secure random bytes for kernel use.
 */
void get_random_bytes(void* buffer, const int length)
{
  ww_generate_bytes(buffer, NULL, length);
}
EXPORT_SYMBOL(get_random_bytes);

/**
 * Generates secure random numbers when the random device is read.
 */
static ssize_t
random_read(struct file* file, char __user* buffer, size_t length, loff_t* offset)
{
  int err = ww_generate_bytes(NULL, buffer, length);
  return (err) ? err : length;
}

/**
 * Does nothing.  All writes to the random device are discarded.  Included here
 * for backwards-compatability.
 */
static ssize_t 
random_write(struct file *file, const char __user *buffer, size_t count, loff_t *ppos)
{
  return (ssize_t)count;
}

/**
 * Returns -EINVAL every time.  No IOCTLs supported.
 */
static long 
random_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
  return -EINVAL;
}

static int 
random_fasync(int fd, struct file *filp, int on)
{
  static struct fasync_struct *fasync;
  return fasync_helper(fd, filp, on, &fasync);
}

const struct file_operations random_fops =
{
  .read  = random_read,
  .write = random_write,
  .unlocked_ioctl = random_ioctl,
  .fasync = random_fasync,
  .llseek = noop_llseek,
};

const struct file_operations urandom_fops =
{
  .read  = random_read,
  .write = random_write,
  .unlocked_ioctl = random_ioctl,
  .fasync = random_fasync,
  .llseek = noop_llseek,
};

/***************************************************************
 * Random UUID interface
 *
 * Used here for a Boot ID, but can be useful for other kernel
 * drivers.
 ***************************************************************/

/**
 * Generate random UUID
 */
void generate_random_uuid(unsigned char uuid_out[16])
{
	get_random_bytes(uuid_out, 16);
	/* Set UUID version to 4 --- truly random generation */
	uuid_out[6] = (uuid_out[6] & 0x0F) | 0x40;
	/* Set the UUID variant to DCE */
	uuid_out[8] = (uuid_out[8] & 0x3F) | 0x80;
}
EXPORT_SYMBOL(generate_random_uuid);

/********************************************************************
 *
 * Sysctl interface
 *
 ********************************************************************/

#ifdef CONFIG_SYSCTL

#include <linux/sysctl.h>

/**
 * This functions is used to return both the bootid UUID, and random
 * UUID.  The difference is in whether table->data is NULL; if it is,
 * then a new UUID is generated and returned to the user.
 *
 * If the user accesses this via the proc interface, it will be returned
 * as an ASCII string in the standard UUID format.  If accesses via the
 * sysctl system call, it is returned as 16 bytes of binary data.
 */
static int 
proc_do_uuid(ctl_table *table, int write,
	     void __user *buffer, size_t *lenp, loff_t *ppos)
{
	ctl_table fake_table;
	unsigned char buf[64], tmp_uuid[16], *uuid;

	uuid = table->data;
	if (!uuid) {
		uuid = tmp_uuid;
		generate_random_uuid(uuid);
	} else {
		static DEFINE_SPINLOCK(bootid_spinlock);

		spin_lock(&bootid_spinlock);
		if (!uuid[8])
			generate_random_uuid(uuid);
		spin_unlock(&bootid_spinlock);
	}

	sprintf(buf, "%pU", uuid);

	fake_table.data = buf;
	fake_table.maxlen = sizeof(buf);

	return proc_dostring(&fake_table, write, buffer, lenp, ppos);
}

static char sysctl_bootid[16];
ctl_table random_table[] = {
	{
		.procname	= "boot_id",
		.data		= &sysctl_bootid,
		.maxlen		= 16,
		.mode		= 0444,
		.proc_handler	= proc_do_uuid,
	},
	{
		.procname	= "uuid",
		.maxlen		= 16,
		.mode		= 0444,
		.proc_handler	= proc_do_uuid,
	},
	{ }
};
#endif 	/* CONFIG_SYSCTL */

/**
 * Retrieves a secure, random integer value.
 */
unsigned long
get_random_ulong(void)
{
   unsigned long r = 0;
   get_random_bytes(&r, sizeof(unsigned long));
   return r;
}
EXPORT_SYMBOL(get_random_ulong);

/**
 * randomize_range() returns a start address such that
 *
 *    [...... <range> .....]
 *  start                  end
 *
 * a <range> with size "len" starting at the return value is inside in the
 * area defined by [start, end], but is otherwise randomized.
 */
unsigned long
randomize_range(const unsigned long start, const unsigned long end, const unsigned long len)
{
  unsigned long range = end - len - start;

  if (end <= start + len)
    return 0;
  return PAGE_ALIGN(get_random_int() % range + start);
}
EXPORT_SYMBOL(randomize_range);
