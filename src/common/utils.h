#ifndef SAFECLOUD_UTILS_H
#define SAFECLOUD_UTILS_H

#include <stdlib.h>

/* SafeCloud Application common utility functions declarations */


/**
 * @brief      Safely erases "size" bytes from address "addr" and resets its value to 'nullptr'
 * @param addr The memory address from where safely erasing data
 * @param size The size in bytes of the data to be safely deleted
 */
void safeErase(void*& addr, unsigned int size);


/**
 * @brief      Safely frees the dynamic memory allocated via a malloc()
 *             referred by a pointer, resetting the latter to 'nullptr'
 * @param pnt  The pointer to the dynamic memory allocated via a malloc()
 * @param size The size in bytes of the dynamic memory allocated via malloc()
 */
void safeFree(void*& pnt,unsigned int size);

#endif //SAFECLOUD_UTILS_H
