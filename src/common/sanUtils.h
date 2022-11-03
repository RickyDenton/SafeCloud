#ifndef SAFECLOUD_SANUTILS_H
#define SAFECLOUD_SANUTILS_H

/* SafeCloud Sanitization Utility Functions Declarations */

/* ================================== INCLUDES ================================== */
#include <string>

/* -------------------------- SUPERSEDED BY OPENSSL_cleanse() -------------------------- */

/**
 * @brief      Safely erases "size" bytes from address
 *             "addr" and resets its value to 'nullptr'
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
 * @brief  Validates a string to represent a valid Linux file name
 * @param  fileName The filename string to be validated
 * @throws ERR_SESS_FILE_INVALID_NAME The string represents an invalid Linux file name
 */
void validateFileName(std::string& fileName);

/**
 * @brief  Sanitizes a SafeCloud username by converting it to lower-case and ensuring that:\n\n
 *           - It is not too long (length <= CLI_NAME_MAX_LENGTH)\n\n
 *           - Its first character consists of a letter of the alphabet (a-z, A-Z)\n\n
 *           - It contains valid characters only (a-z, A-Z, 0-9, _)
 * @param  username The address of the username to sanitize
 * @throws ERR_LOGIN_NAME_EMPTY         Username is empty
 * @throws ERR_LOGIN_NAME_TOO_LONG      Username it too long
 * @throws ERR_LOGIN_NAME_WRONG_FORMAT  First non-alphabet character in the username
 * @throws ERR_LOGIN_NAME_INVALID_CHARS Invalid characters in the username
 */
void sanitizeUsername(std::string& username);


#endif //SAFECLOUD_SANUTILS_H