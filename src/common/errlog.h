#ifndef SAFECLOUD_ERRLOG_H
#define SAFECLOUD_ERRLOG_H

/* SafeCloud application error logging macros */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include <map>
#include <utility>
#include <string.h>
#include "colors.h"
#include "scode.h"
#include <openssl/err.h>

/* =========================== LOGGING UTILITY MACROS =========================== */

// Returns a human-readable description of the error stored in the 'errno' global variable
#define ERRNO_DESC strerror(errno)

/* ---------------------------- OpenSSL Error Logging ---------------------------- */
// Returns the last OpenSSL error code
#define OSSL_ERR_CODE ERR_get_error()

// Returns a human-readable error description of the last OpenSSL error code
#define OSSL_ERR_DESC ERR_error_string(ERR_get_error(),NULL) \

/* -------------------- scodeExceptions Throwing and Catching -------------------- */

/**
 * THROW_SCODE macros, throwing scode exceptions containing, depending on the number of arguments passed to the THROW_SCODE macro:
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
#define CATCH_LOG_SCODE    \
catch(sCodeException& e)   \
 { handleScodeError(e); }

/* -------------------- SEVERITY-BASED CUSTOM STRING LOGGING -------------------- */

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


/* ============================ FUNCTIONS DEFINITIONS ============================ */

extern void terminate(int exit_status);

/**
 * @brief Prints the predefined formatted logging header associated
 *        with a severity level (handleScodeError() helper function)
 * @param sev The severity level
 */
void printSevLevHeader(severityLvl sev)
 {
  switch(sev)
   {
    case FATAL:
     std::cout << BOLDBRIGHTRED << "<FATAL> " << BRIGHTRED;
    break;

    case CRITICAL:
     std::cout << BOLDBRIGHTRED << "<CRITICAL> " << BRIGHTRED;
    break;

    case ERROR:
     std::cout << BOLDRED << "<ERROR> " << RED;
    break;

    case WARNING:
     std::cout << BOLDYELLOW << "<WARNING> " << YELLOW;
    break;

    case INFO:
     std::cout << "<INFO> ";
    break;

    case DEBUG:
     std::cout << BOLDBRIGHTBLACK << "<DEBUG> " << BRIGHTBLACK;
    break;

    // Unknown severity level (a fatal error of itself)
    default:
     std::cerr << "<FATAL> UNKNOWN SECURITY LEVEL in printSevLevHeader() (" + std::to_string(sev) + ")" << std::endl;
    exit(EXIT_FAILURE);
   }
 }


/**
 * @brief      scodeException default handler, which:\n
 *                1) Logs all information associated with the scodeException, including:\n
 *                    1. The severity level of its status code\n
 *                    2. The human-readable description associated with its status code\n
 *                    3. (if available) The additional description provided to the scodeException\n
 *                    4. (if available) The error reason provided to the scodeException\n
 *                    5. (if DEBUG_MODE) The source file name and line number at which the scodeException was thrown\n
 *                2) For status codes of FATAL severity, the application's shutdown handler is invoked (terminate() function)\n
 * @param excp The handled scodeException object
 */
void handleScodeError(const sCodeException& excp)
 {
  // Obtain an iterator to the entry of the scodeInfoMap associated with the exception's status code
  auto scodeInfoMapIt = scodeInfoMap.find(excp.scode);

  // Retrieve the status code's severity level and description
  enum severityLvl sev = scodeInfoMapIt->second.sev;
  const char*dscr = scodeInfoMapIt->second.dscr;

  // Print the logging header associated with the status code's security level
  printSevLevHeader(sev);

  // Print the status code's error description
  std::cout << dscr;

  // If present, log the additional description and error reason associated with the exception
  if(!excp.addDscr.empty())
   {
    if(!excp.reason.empty())
     std::cout << " (" << excp.addDscr << ", reason: " << excp.reason << ")";
    else
     std::cout << " (" << excp.addDscr << ")";
   }

  // In DEBUG_MODE, print the source file name and line number at which the exception was thrown
#ifdef DEBUG_MODE
  std::cout << " (file: \"" << excp.srcFile << "\", line: " << excp.lineNumber << ")";
#endif

  // Print the error logging trailer
  std::cout << RESET << std::endl;

  // For scode of FATAL severity, call the application's shutdown handler
  if(sev == FATAL)
   terminate(EXIT_FAILURE);

  // NOTE: Exception objects are automatically destroyed after handling (matching
  //       catch{} clause), and so do not require to be manually deallocated
 }

#endif //SAFECLOUD_ERRLOG_H
