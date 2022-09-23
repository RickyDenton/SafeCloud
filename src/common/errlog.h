#ifndef SAFECLOUD_ERRLOG_H
#define SAFECLOUD_ERRLOG_H

/* SafeCloud application error utilities definitions */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include <map>
#include <utility>
#include <string.h>
#include "ansi_colors.h"
#include "scode.h"
#include <openssl/err.h>
#include "defaults.h"

/* =========================== LOGGING UTILITY MACROS =========================== */

// Returns a human-readable description of the error stored in the 'errno' global variable
#define ERRNO_DESC strerror(errno)

/* ---------------------------- OpenSSL Error Logging ---------------------------- */
// Returns the last OpenSSL error code
#define OSSL_ERR_CODE ERR_get_error()

// Returns a human-readable error description of the last OpenSSL error code
#define OSSL_ERR_DESC ERR_error_string(ERR_get_error(),NULL) \

/* ------------------------------- LOG_SCODE Macros ------------------------------- */

/**
 * LOG_SCODE macros, calling the throwing scode exceptions containing, depending on the number of arguments passed to the THROW_SCODE macro:
 *  - 1 argument   -> scode only
 *  - 2 arguments  -> scode + additional description
 *  - 3 arguments  -> scode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
 #define LOG_SCODE_ONLY(scode) handleScodeError(scode,"","",__FILE__,__LINE__-1)
 #define LOG_SCODE_DSCR(scode,dscr) handleScodeError(scode,dscr,"",__FILE__,__LINE__-1)
 #define LOG_SCODE_DSCR_REASON(scode,dscr,reason) handleScodeError(scode,dscr,reason,__FILE__,__LINE__-1)
#else
#define LOG_SCODE_ONLY(scode) handleScodeError(scode,"","")
 #define LOG_SCODE_DSCR(scode,dscr) handleScodeError(scode,dscr,"")
 #define LOG_SCODE_DSCR_REASON(scode,dscr,reason) handleScodeError(scode,dscr,reason)
#endif

/**
 * Substitutes the appropriate LOG_SCODE_MACRO depending on the number of arguments passed to the LOG_SCODE variadic macro:
 *  - 1 argument  -> scode only
 *  - 2 arguments -> scode + additional description
 *  - 3 arguments -> scode + additional description + error reason
 */
#define GET_LOG_SCODE_MACRO(_1,_2,_3,LOG_SCODE_MACRO,...) LOG_SCODE_MACRO
#define LOG_SCODE(...) GET_LOG_SCODE_MACRO(__VA_ARGS__,LOG_SCODE_DSCR_REASON,LOG_SCODE_DSCR,LOG_SCODE_ONLY)(__VA_ARGS__)


/* -------------------- scodeExceptions Throwing and Catching -------------------- */

/**
 * THROW_SCODE macros, passing their arguments to the handleScodeException() function:
 *  - 1 argument   -> scode only
 *  - 2 arguments  -> scode + additional description
 *  - 3 arguments  -> scode + additional description + error reason
 *  - (DEBUG_MODE) -> The source file name and line number at which the exception is thrown
 */
#ifdef DEBUG_MODE
#define THROW_SCODE_ONLY(scode) throw sCodeException(scode,__FILE__,__LINE__-1)
 #define THROW_SCODE_DSCR(scode,dscr) throw sCodeException(scode,dscr,__FILE__,__LINE__-1)
 #define THROW_SCODE_DSCR_REASON(scode,dscr,reason) throw sCodeException(scode,dscr,reason,__FILE__,__LINE__-1)
#else
#define THROW_SCODE_ONLY(scode) throw sCodeException(scode)
 #define THROW_SCODE_DSCR(scode,dscr) throw sCodeException(scode,dscr)
 #define THROW_SCODE_DSCR_REASON(scode,dscr,reason) throw sCodeException(scode,dscr,reason)
#endif


/**
 * Substitutes the appropriate THROW_SCODE_MACRO depending on the number of arguments passed to the THROW_SCODE variadic macro:
 *  - 1 argument  -> scode only
 *  - 2 arguments -> scode + additional description
 *  - 3 arguments -> scode + additional description + error reason
 */
#define GET_THROW_SCODE_MACRO(_1,_2,_3,THROW_SCODE_MACRO,...) THROW_SCODE_MACRO
#define THROW_SCODE(...) GET_THROW_SCODE_MACRO(__VA_ARGS__,THROW_SCODE_DSCR_REASON,THROW_SCODE_DSCR,THROW_SCODE_ONLY)(__VA_ARGS__)

/*
 * Catches a scodeException and passes it to the default scode error handler
 */
#define CATCH_SCODE              \
catch(sCodeException& excp)      \
 { handleScodeException(excp); }


/* -------------------- Severity-based Custom String Logging -------------------- */

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


/* ============================== TYPE DEFINITIONS ============================== */

/**
 * @brief An exception associated with a SafeCloud error status code and possibly additional information
 */
class sCodeException : public std::exception
 {
   public:

  /* ========================= Attributes ========================= */
  enum scode  scode;       // The SafeCloud error status code associated with the exception (severity >= WARNING)
  std::string addDscr;     // An additional description associated with the error that has occurred (optional)
  std::string reason;      // An additional reason associated with the error that has occurred (optional)

/* In DEBUG_MODE a sCodeException also carries the source file name and the line number at which the exception was raised */
#ifdef DEBUG_MODE
  std::string srcFile;     // Source file name that has raised the exception
  unsigned int lineNumber; // Line in the source file the exception has been raised at
#endif

  /* ================= Constructors and Destructor ================= */

  /* ----------------- Non-DEBUG_MODE Constructors ----------------- */
#ifndef DEBUG_MODE
  // scode-only constructor (with implicit source file name and line)
  explicit sCodeException(const enum scode scodeExcept) : scode(scodeExcept)
   {}

  // scode + additional description constructor (with implicit source file name and line)
  sCodeException(const enum scode scodeExcept, std::string addDescr) : scode(scodeExcept), addDscr(std::move(addDescr))
   {}

  // scode + additional description + reason constructor (with implicit source file name and line)
  sCodeException(const enum scode scodeExcept, std::string addDescr, std::string errReason) : scode(scodeExcept), addDscr(std::move(addDescr)), reason(std::move(errReason))
   {}
#else
  /* ------------------- DEBUG_MODE Constructors ------------------- */

  // scode-only constructor (with implicit source file name and line)
  explicit sCodeException(const enum scode scodeExcept, std::string srcFileName,const unsigned int line)
    : scode(scodeExcept), srcFile(std::move(srcFileName)), lineNumber(line)
   {}

  // scode + additional description constructor (with implicit source file name and line)
  sCodeException(const enum scode scodeExcept, std::string addDescr, std::string srcFileName, const unsigned int line)
    : scode(scodeExcept), addDscr(std::move(addDescr)), srcFile(std::move(srcFileName)), lineNumber(line)
   {}

  // scode + additional description + reason constructor (with implicit source file name and line)
  sCodeException(const enum scode scodeExcept, std::string addDescr, std::string errReason, std::string srcFileName, const unsigned int line)
    : scode(scodeExcept), addDscr(std::move(addDescr)), reason(std::move(errReason)), srcFile(std::move(srcFileName)), lineNumber(line)
   {}
#endif
 };


/* =========================== FUNCTIONS DECLARATIONS =========================== */

/**
 * @brief            SafeCloud application default error handler, which:\n
 *                     1) Logs all information associated with the error, including:\n
 *                        1. The severity level of its associated status code\n
 *                        2. The human-readable description of the associated status code\n
 *                        3. (if available) The provided additional error description\n
 *                        4. (if available) The provided error reason\n
 *                        5. (if DEBUG_MODE) The source file name and line number at which the error occurred at\n
 *                     2) For status codes of FATAL severity, the application's shutdown handler is invoked (terminate() function)\n
 * @param sCode      The error's status code
 * @param addDsc     The additional error description (optional)
 * @param reason     The error reason (optional)
 * @param srcFile    (DEBUG MODE ONLY) The source file the error occurred at
 * @param lineNumber (DEBUG MODE ONLY) The line number the error occurred at
 */
#ifdef DEBUG_MODE
void handleScodeError(enum scode sCode,const std::string& addDscr,const std::string& reason,const std::string& srcFile,unsigned int lineNumber);
#else
void handleScodeError(enum scode sCode,const std::string& addDscr,const std::string& reason);
#endif


/**
 * @brief      scodeException default handler, passing all information in the exception
 *             to the SafeCloud application default error handler handleScodeError():\n
 * @param excp The handled scodeException object
 */
void handleScodeException(const sCodeException& excp);


#endif //SAFECLOUD_ERRLOG_H
