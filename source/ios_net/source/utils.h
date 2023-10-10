#pragma once

#include <stddef.h>

void dumpHex(const void* data, size_t size);

#define ALIGN(val, to) (((val) + (to-1)) & ~(to-1))
