/* SafeCloud Application sanitization utility functions definitions */

/* ================================== INCLUDES ================================== */
#include <cctype>
#include <string>
#include "sanUtils.h"
#include "defaults.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"
#include <bits/stdc++.h>


/* -------------------------- SUPERSEDED BY OPENSSL_cleanse() -------------------------- */

/**
 * @brief      Safely erases "size" bytes from address "addr" and resets its value to 'nullptr'
 * @param addr The memory address from where safely erasing data
 * @param size The size in bytes of the data to be safely deleted
 */
//void safeMemset0(void*& addr, unsigned int size)
// {
//#pragma optimize("", off)
//  if(addr != nullptr)
//   {
//    memset(addr, 0, size);
//    addr = nullptr;
//   }
//#pragma optimize("", on)
// }


/**
 * @brief      Safely frees the dynamic memory allocated via a malloc()
 *             referred by a pointer, resetting the latter to 'nullptr'
 * @param pnt  The pointer to the dynamic memory allocated via a malloc()
 * @param size The size in bytes of the dynamic memory allocated via malloc()
 */
//void safeFree(void*& pnt,unsigned int size)
// {
//  void* pntBak = pnt;   // Pointer copy to call the free() after the safeErase()
//
//  if(pnt != nullptr)
//   {
//    safeMemset0(pnt, size);
//    free(pntBak);
//   }
// }

/* -------------------------- SUPERSEDED BY OPENSSL_cleanse() -------------------------- */


/**
 * @brief Validates a string to represent a valid Linux file name
 * @param fileName The filename string to be validated
 * @throws ERR_SESS_FILE_INVALID_NAME The string represents an invalid Linux file name
 */
void validateFileName(std::string& fileName)
 {
  // A file name cannot be null
  if(fileName.empty())
   THROW_SESS_EXCP(ERR_SESS_FILE_INVALID_NAME,"empty file name");

  // A file name cannot exceed the Linux-defined maximum file name length
  if(fileName.length() > NAME_MAX)
   THROW_SESS_EXCP(ERR_SESS_FILE_INVALID_NAME,"\"" + fileName + "\"","filename of length "
                                              + std::to_string(fileName.length())
                                              + " > NAME_MAX = " + std::to_string((NAME_MAX)));

  // A file name cannot consist of the current or the parent's directory
  if(fileName == "." || fileName == "..")
   THROW_SESS_EXCP(ERR_SESS_FILE_INVALID_NAME,"\"" + fileName + "\"",
                                              "current or parent directory referencing");

  // A file name cannot contain '/' or '\0' characters
  for(auto& ch : fileName)
   if(ch == '/' || ch == '\0')
    THROW_SESS_EXCP(ERR_SESS_FILE_INVALID_NAME,"\"" + fileName + "\"",
                                               "invalid '/' or '\\0' characters");
 }


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
void sanitizeUsername(std::string& username)
 {
  static char validNameChars[] = "abcdefghijklmnopqrstuvwxyz"
                                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                 "1234567890_";

  // Ensure the username not to be empty
  if(username.empty())
   THROW_EXEC_EXCP(ERR_LOGIN_NAME_EMPTY);

  // Ensure the username not to be too long
  if(username.length() > CLI_NAME_MAX_LENGTH)
   THROW_EXEC_EXCP(ERR_LOGIN_NAME_TOO_LONG);

  // Ensure the first character to consist of a letter of the alphabet (a-z, A-Z)
  if(!isalpha(username.front()))
   THROW_EXEC_EXCP(ERR_LOGIN_NAME_WRONG_FORMAT);

  // Ensure the username to contain valid characters only (a-z, A-Z, 0-9, _)
  if(username.find_first_not_of(validNameChars) != std::string::npos)
   THROW_EXEC_EXCP(ERR_LOGIN_NAME_INVALID_CHARS);

  // Convert the username to lowercase
  transform(username.begin(), username.end(), username.begin(), ::tolower);
 }
