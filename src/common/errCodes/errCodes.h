#ifndef SAFECLOUD_ERRCODES_H
#define SAFECLOUD_ERRCODES_H

/* SafeCloud Generic Error Codes Declarations */

#include <openssl/err.h>
#include <iostream>
#include <string.h>
#include "ansi_colors.h"

/* ============================== TYPE DEFINITIONS ============================== */

/* ------------------- SafeCloud Error Codes Severity Levels ------------------- */
enum errCodeSeverity : unsigned char
 {
  FATAL,     // Unrecoverable error, the application must be terminated
  CRITICAL,  // Unrecoverable error
  ERROR,     // Recoverable error
  WARNING,   // Unexpected event
  INFO,      // Informational content
  DEBUG      // Debug content
 };

/* ------------------------ SafeCloud Errors Information ------------------------ */

// Used for associating a severity level and a
// human-readable description to error codes
struct errCodeInfo
 {
  enum errCodeSeverity sevLev;    // The error code severity level (FATAL to INFO)
  const char*          humanDscr; // The error code human-readable description
 };

/* --------------- SafeCloud Error Exceptions Base Virtual Class --------------- */

/**
 * @brief An abstract exception class that can be derived so to throw error
 *        status codes with an optional additional description and reason
 * @note  The dynamic strings allocated in calling this function are deallocated
 *        within the SafeCloud default error handler (handleErrCode() function)
 */
class errExcp : public std::exception
 {
   public:

   /* ========================= Attributes ========================= */
   std::string* addDscr;     // An optional description associated with the error that has occurred
   std::string* reason;      // An optional reason associated with the error that has occurred

/* In DEBUG_MODE a errExcp also carries the source file name
 * and the line number at which the exception has been raised
 */
#ifdef DEBUG_MODE
  std::string* srcFile;     // Source file name where the exception has been raised
  unsigned int lineNumber; // Line in the source file at which the exception has been raised
#endif

  /* ================= Constructors and Destructor ================= */

#ifdef DEBUG_MODE
  /* ------------------- DEBUG_MODE Constructors ------------------- */

  // No optional fields' constructor (implicit source file name and line only)
  errExcp(std::string* srcFileName, const unsigned int line)
    : srcFile(srcFileName), addDscr(nullptr), reason(nullptr), lineNumber(line)
   {}

  // Additional description constructor (with implicit source file name and line)
  errExcp(std::string* addDescr, std::string* srcFileName, const unsigned int line)
    : addDscr(addDescr), srcFile(srcFileName), reason(nullptr), lineNumber(line)
   {}

  // Additional description + reason constructor (with implicit source file name and line)
  errExcp(std::string* addDescr, std::string* errReason, std::string* srcFileName, const unsigned int line)
    : addDscr(addDescr), reason(errReason), srcFile(srcFileName), lineNumber(line)
   {}
#else
  /* ----------------- Non-DEBUG_MODE Constructors ----------------- */

  // Empty constructor
  errExcp() : addDscr(nullptr), reason(nullptr)
   {}

  // Additional description constructor
  explicit errExcp(std::string* addDescr) : addDscr(addDescr), reason(nullptr)
   {}

  // Additional description + reason constructor
  errExcp(std::string* addDescr, std::string* errReason) : addDscr(addDescr), reason(errReason)
   {}
#endif
 };


/* ============================ ERROR LOGGING MACROS ============================ */

/* ------------------------ Utility Error Logging Macros ------------------------ */

// Returns a human-readable description of the error stored in the 'errno' global variable
#define ERRNO_DESC strerror(errno)

// Returns a human-readable error description of the last OpenSSL error code
#define OSSL_ERR_DESC ERR_error_string(ERR_get_error(),NULL)

/* ----------------- Severity-based Custom Error Logging Macros ----------------- */

// In DEBUG_MODE LOG_SEVERITY macros also print the name and line of the file where the LOG was called
#ifdef DEBUG_MODE
 #define FILE_LINE_DEBUG " (file: \"" << __FILE__ << "\", line: " << std::to_string(__LINE__) << ")"
#else
 #define FILE_LINE_DEBUG " "
#endif

#define LOG_FATAL(logStr)                                                          \
 std::cout << BOLDBRIGHTRED << "<FATAL> " << BRIGHTRED << (logStr) << FILE_LINE_DEBUG << RESET << std::endl;

#define LOG_CRITICAL(logStr)                                                       \
 std::cout << BOLDBRIGHTRED << "<CRITICAL> " << BRIGHTRED << (logStr) << FILE_LINE_DEBUG << RESET << std::endl;

#define LOG_ERROR(logStr)                                                          \
 std::cout << BOLDRED << "<ERROR> " << RED << (logStr) << FILE_LINE_DEBUG << RESET << std::endl;

#define LOG_WARNING(logStr)                                                        \
 std::cout << BOLDYELLOW << "<WARNING> " << YELLOW << (logStr) << FILE_LINE_DEBUG << RESET << std::endl;

#define LOG_INFO(logStr)                                                           \
 std::cout << "<INFO> " << (logStr)  << std::endl;                                            \

// NOTE: LOG_DEBUG outputs in DEBUG_MODE only
#ifdef DEBUG_MODE
#define LOG_DEBUG(logStr)                                                        \
  std::cout << BOLDBRIGHTBLACK << "<DEBUG> " << BRIGHTBLACK << (logStr) << RESET << std::endl;
#else
 #define LOG_DEBUG(logStr) ;
#endif

/* =========================== FUNCTIONS DECLARATIONS =========================== */

/**
 * @brief            SafeCloud application default error handler, which:\n
 *                     1) Logs all information associated with the error, including:\n
 *                        1. The severity level of the associated error code\n
 *                        2. The human-readable description of the associated error code\n
 *                        3. (if available) The additional error description\n
 *                        4. (if available) The error reason\n
 *                        5. (if DEBUG_MODE) The source file name and line number at which the error has occurred\n
 *                     2) For errors codes of FATAL severity, the SafeCloud application is
 *                        terminated by invoking the default shutdown handler (terminate() function)
 * @param errInf     The severity level and human-readable description of the associated error code
 * @param addDsc     The additional error description (optional)
 * @param reason     The error reason (optional)
 * @param srcFile    (DEBUG MODE ONLY) The source file where the error has occurred
 * @param lineNumber (DEBUG MODE ONLY) The line number at which the error has occurred
 */
#ifdef DEBUG_MODE
void handleErrCode(const errCodeInfo errInf, const std::string* addDscr, const std::string* reason, const std::string* srcFile, const unsigned int lineNumber);
#else
void handleErrCode(const errCodeInfo errInf,const std::string* addDscr,const std::string* reason);
#endif


#endif //SAFECLOUD_ERRCODES_H