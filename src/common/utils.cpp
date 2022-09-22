/* SafeCloud Application common utility functions definitions */

#include <string.h>
#include <cctype>
#include <string>
#include "utils.h"
#include "defaults.h"
#include "errlog.h"
#include<bits/stdc++.h>

/**
 * @brief      Safely erases "size" bytes from address "addr" and resets its value to 'nullptr'
 * @param addr The memory address from where safely erasing data
 * @param size The size in bytes of the data to be safely deleted
 */
void safeMemset0(void*& addr, unsigned int size)
 {
#pragma optimize("", off)
  memset(addr, 0, size);
  addr = nullptr;
#pragma optimize("", on)
 }


/**
 * @brief      Safely frees the dynamic memory allocated via a malloc()
 *             referred by a pointer, resetting the latter to 'nullptr'
 * @param pnt  The pointer to the dynamic memory allocated via a malloc()
 * @param size The size in bytes of the dynamic memory allocated via malloc()
 */
void safeFree(void*& pnt,unsigned int size)
 {
  void* pntBak = pnt;   // Pointer copy to call the free() after the safeErase()

  if(pnt != nullptr)
   {
    safeMemset0(pnt, size);
    free(pntBak);
   }
 }


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
void sanitizeUsername(std::string& username)
 {
  static char validNameChars[] = "abcdefghijklmnopqrstuvwxyz"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "1234567890_";

  // Ensure the username not to be too long
  if(username.length() > CLI_NAME_MAX_LENGTH)
   throw sCodeException(ERR_LOGIN_NAME_TOO_LONG);

  // Ensure the first character to consist of a letter of the alphabet (a-z, A-Z)
  if(!isalpha(username.front()))
   throw sCodeException(ERR_LOGIN_NAME_WRONG_FORMAT);

  // Ensure the username to contain valid characters only (a-z, A-Z, 0-9, _)
  if(username.find_first_not_of(validNameChars) != std::string::npos)
   throw sCodeException(ERR_LOGIN_NAME_INVALID_CHARS);

  // Convert the username to lowercase
  transform(username.begin(), username.end(), username.begin(), ::tolower);
 }