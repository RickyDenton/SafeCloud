/* SafeCloud Application common utility functions definitions */

#include <string.h>
#include "utils.h"


/**
 * @brief      Safely deletes "size" bytes from address "addr" by zeroing them
 * @param addr The starting address to safely delete from
 * @param size The number of bytes to safely delete
 */
void safeFree(void* addr,unsigned int size)
 {
#pragma optimize("", off)
 memset(addr, 0, size);
#pragma optimize("", on)
 }