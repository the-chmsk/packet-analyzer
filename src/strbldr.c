/*
 * This file is part of packet-analyzer.
 *
 * Copyright (C) 2024  Oliver Ulrich
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "strbldr.h"

sb_t sb_create() {
  // Allocate new sb_t with initial size nad 1 place for null terminator.
  sb_t sb = (sb_t)malloc(sizeof(sb_t) + SB_INIT_SIZE);

  if (sb == NULL)
    return NULL;

  sb->size = SB_INIT_SIZE;
  sb->pos = 0;
  sb->buf[0] = '\0';

  return sb;
}

void sb_destroy(sb_t sb) {
  if (sb == NULL) {
    return;
  }

  free(sb);
}

void sb_extend(sb_t *sb) {
  (*sb)->size *= 2;
  *sb = realloc(*sb, sizeof(struct sb) + (*sb)->size);
}

void sb_append_string(sb_t *sb, const char *str) {
  size_t size = strlen(str);
  while ((*sb)->size - (*sb)->pos < size + 1) {
    sb_extend(sb);
  }

  strcpy(&((*sb)->buf[(*sb)->pos]), str);

  (*sb)->pos += size;
}

void sb_append_char(sb_t *sb, const char c) {
  if ((*sb)->size - (*sb)->pos < 1) {
    sb_extend(sb);
  }

  (*sb)->buf[(*sb)->pos++] = c;
  (*sb)->buf[(*sb)->pos] = '\0';
}

char *sb_get_string(sb_t sb) {
  char *str = malloc(sb->pos + 1);
  if (str == NULL)
    return NULL;

  memcpy(str, sb->buf, sb->pos + 1);

  return str;
}