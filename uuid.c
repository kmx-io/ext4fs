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
#include <stdio.h>

#include "../include/uuid.h"

void arc4random_buf(void *buf, size_t n);

void uuid_print(const uint8_t uuid[16]) {
  printf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-"
         "%02x%02x%02x%02x%02x%02x\n",
         uuid[0], uuid[1], uuid[2], uuid[3],
         uuid[4], uuid[5],
         uuid[6], uuid[7],
         uuid[8], uuid[9],
         uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
}

void uuid_v4_gen(uint8_t uuid[16]) {
  arc4random_buf(uuid, 16);
  uuid[6] = (uuid[6] & 0x0F) | 0x40; // Set UUID version to 4 (0100xxxx)
  uuid[8] = (uuid[8] & 0x3F) | 0x80; // Set UUID variant to RFC 4122 (10xxxxxx)
}
