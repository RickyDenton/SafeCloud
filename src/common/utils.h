#ifndef SAFECLOUD_UTILS_H
#define SAFECLOUD_UTILS_H

#include <stdlib.h>

/* SafeCloud Application common utility functions declarations */


/**
 * @brief      Safely erases "size" bytes from address "addr" and resets its value to 'nullptr'
 * @param addr The memory address from where safely erasing data
 * @param size The size in bytes of the data to be safely deleted
 */
void safeMemset0(void*& addr, unsigned int size);


/**
 * @brief      Safely frees the dynamic memory allocated via a malloc()
 *             referred by a pointer, resetting the latter to 'nullptr'
 * @param pnt  The pointer to the dynamic memory allocated via a malloc()
 * @param size The size in bytes of the dynamic memory allocated via malloc()
 */
void safeFree(void*& pnt,unsigned int size);


/**
 * @brief Sanitizes a SafeCloud username by converting it to lower-case and ensuring that:\n
 *        - It is not too long (length <= CLI_NAME_MAX_LENGTH)\name
 *        - Its first character consists of a letter of the alphabet (a-z, A-Z)
 *        - It contains valid characters only (a-z, A-Z, 0-9, _)
 * @param username The address of the username to sanitize
 * @throws Username too long => sCodeException(ERR_LOGIN_NAME_TOO_LONG) →
 * @throws First non-alphabet character => sCodeException(ERR_LOGIN_NAME_WRONG_FORMAT)
 * @throws Invalid characters => sCodeException(ERR_LOGIN_NAME_INVALID_CHARS)
 */
void sanitizeUsername(std::string& username);


#endif //SAFECLOUD_UTILS_H
