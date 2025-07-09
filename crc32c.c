/* ext4fs
 * Copyright 2025 kmx.io <contact@kmx.io>
 *
 * Permission is hereby granted to use this software granted the above
 * copyright notice and this permission paragraph are included in all
 * copies and substantial portions of this software.
 *
 * THIS SOFTWARE IS PROVIDED "AS-IS" WITHOUT ANY GUARANTEE OF
 * PURPOSE AND PERFORMANCE. IN NO EVENT WHATSOEVER SHALL THE
 * AUTHOR BE CONSIDERED LIABLE FOR THE USE AND PERFORMANCE OF
 * THIS SOFTWARE.
 */
#include <crc32c.h>

#include "../crc32c_table/crc32c_table.h"

uint32_t crc32c (uint32_t crc, const void *data, size_t len)
{
  const uint8_t *p = data;
  crc = ~crc;
  while (len--)
    crc = (crc >> 8) ^ crc32c_table[(crc & 0xFF) ^ *p++];
  return ~crc;
}
