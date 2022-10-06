#ifndef SAFECLOUD_UTILS_H
#define SAFECLOUD_UTILS_H

#include <stdlib.h>
#include <string>

/* SafeCloud Application common utility functions declarations */


/* -------------------------- SUPERSEDED BY OPENSSL_cleanse() -------------------------- */

/**
 * @brief      Safely erases "size" bytes from address "addr" and resets its value to 'nullptr'
 * @param addr The memory address from where safely erasing data
 * @param size The size in bytes of the data to be safely deleted
 */
//void safeMemset0(void*& addr, unsigned int size);


/**
 * @brief      Safely frees the dynamic memory allocated via a malloc()
 *             referred by a pointer, resetting the latter to 'nullptr'
 * @param pnt  The pointer to the dynamic memory allocated via a malloc()
 * @param size The size in bytes of the dynamic memory allocated via malloc()
 */
//void safeFree(void*& pnt,unsigned int size);

/* -------------------------- SUPERSEDED BY OPENSSL_cleanse() -------------------------- */


/**
 * @brief Sanitizes a SafeCloud username by converting it to lower-case and ensuring that:\n
 *        - It is not too long (length <= CLI_NAME_MAX_LENGTH)\name
 *        - Its first character consists of a letter of the alphabet (a-z, A-Z)
 *        - It contains valid characters only (a-z, A-Z, 0-9, _)
 * @param username The address of the username to sanitize
 * @throws ERR_LOGIN_NAME_EMPTY         Username is empty
 * @throws ERR_LOGIN_NAME_TOO_LONG      Username it too long
 * @throws ERR_LOGIN_NAME_WRONG_FORMAT  First non-alphabet character in the username
 * @throws ERR_LOGIN_NAME_INVALID_CHARS Invalid characters in the username
 */
void sanitizeUsername(std::string& username);


#endif //SAFECLOUD_UTILS_H
