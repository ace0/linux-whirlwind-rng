/*
 * swiftbuffer.c -- Whirlwind is a secure random number generator.
 * SwiftBuffer is an optimized procedure for compacting and rapidly buffering
 * inputs from interrupt events that can be later processed by less performance-
 * sensitive RNG events.
 *
 * Copyright (C) Adam C Everspaugh <ace@cs.wisc.edu>, 2014.  All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include "whirlwind.h"
#include "whirlwind-internal.h"

#define SWIFT_BUFFER_BYTES 1024

// Computes the minimum number of bytes required to represent
// a specified @value.
#define min_bytes(value) ((fls64(value) + 7) / 8)

// Get an index to the next free position in swift buffer.
#define sb_write_index (total_bytes % SWIFT_BUFFER_BYTES)

// We need to reserve 7 bonus bytes at the end of the buffer to ensure that the 
// (optimized) delta_cc copy doesn't exceed the length to the buffer.
static u8 buffer[SWIFT_BUFFER_BYTES+sizeof(u64)-1];
static unsigned long long int total_bytes;
//static bool buffer_full = 0;
//static u64 previous_rip = 0;

// Append a single byte to the swift buffer.
#define swift_buffer_append_byte(value) \
  buffer[sb_write_index] = value; \
  total_bytes++;

/**
 * Rapidly compact inputs from this interrupt and append them to our large
 * buffer so they can be processed later when less time-sensitive RNG events
 * occur (like other inputs or any output events).
 */
void sb_add_interrupt_randomness(int irq, int irq_flags)
{
  // Storing the previous cycle counter lets us keep only delta cycle counters
  // in the swift buffer.  This captures all the entropy in a sequence of cycle
  // and is vastly more space efficient.
  static cycles_t previous_cc = 0;

  // unsigned long now = jiffies;
  cycles_t cycles = get_cycles();
  struct pt_regs *regs = get_irq_regs();
  unsigned long rip = regs ? instruction_pointer(regs) : _RET_IP_;
  u64 delta_cc = 0;

  // Combine each byte of the flags and RIP into a single byte
  // since they are higly correlated and low-entropy values.
  u64 a = irq_flags ^ rip;
  u32 b = (a >> 32) ^ a;
  u16 c = (b >> 16) ^ b;
  u8  d = (c >> 8)  ^ c;

  // Keep the low byte of the IRQ as a source ID.
  swift_buffer_append_byte((u8)irq);
  swift_buffer_append_byte(d);

  // Compute the delta CC and make sure all the information bits are in the upper 
  // bits (little-endian). By copying only information bearing bytes, this excludes 
  // having any bytes with only leading zeroes in the swift buffer.
  delta_cc = cpu_to_le64(cycles - previous_cc);

  // Copy all the bytes into the swift buffer, but only keep
  // the non-zero bytes.  We can get away with this without
  // overflowing the buffer because the swift buffer was
  // initialized with 7 bonus bytes for this specific purpose.
  // This might look like a hack, but my test platform shows
  // a 30 cycles/interrupt performance gain (~50%).
  *((u64*)(buffer + sb_write_index)) = delta_cc;
  total_bytes += min_bytes(delta_cc);

  // Record this cycle counter for posterity.
  previous_cc = cycles;

  // Move this segment tracking logic to the buffer flush
  // routine.
  // If the write index has wrapped, mark the buffer as full.
  // if (unlikely(write_index < starting_index))
  // {
  //      buffer_full = true;
  // }
}
