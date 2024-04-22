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

#ifndef STRBLDR_H
#define STRBLDR_H

#include <stdlib.h>
#include <string.h>

// String builder structure.
struct sb {
  size_t size;
  size_t pos;
  char buf[];
};

typedef struct sb *sb_t;

#define SB_INIT_SIZE 20 // Initial buffer size.

// Allocate and return new string builder.
sb_t sb_create();

// Free string builder resources.
void sb_destroy(sb_t sb);

// Append a string to a string builder.
void sb_append_string(sb_t *sb, const char *str);

// Append a character to a string builder.
void sb_append_char(sb_t *sb, const char c);

// Return builded string including null terminator at the end.
// The caller is responsible for freeing the memory pointed to by the returned
// pointer.
char *sb_get_string(sb_t sb);

#endif