/* SafeCloud application error utilities implementations */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include <map>
#include "ansi_colors.h"
#include "scode.h"
#include "errlog.h"
#include <openssl/err.h>

/* ============================ FORWARD DECLARATIONS ============================ */
extern void terminate(int exit_status);   // SafeCloud application shutdown function


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief Prints the predefined formatted logging header associated
 *        with a severity level (handleScodeException() helper function)
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
void handleScodeError(const enum scode sCode,const std::string& addDscr,const std::string& reason,const std::string& srcFile,const unsigned int lineNumber)
#else
void handleScodeError(const enum scode sCode,const std::string& addDscr,const std::string& reason)
#endif
 {
  // Obtain an iterator to the entry of the scodeInfoMap associated with the exception's status code
  auto scodeInfoMapIt = scodeInfoMap.find(sCode);

  // Retrieve the status code's severity level and description
  enum severityLvl sev = scodeInfoMapIt->second.sev;
  std::string dscr = scodeInfoMapIt->second.dscr;

  // Print the logging header associated with the status code's security level
  printSevLevHeader(sev);

  // Print the status code's error description
  std::cout << dscr;

  // If present, log the additional description and error reason associated with the exception
  if(!addDscr.empty())
   {
    if(!reason.empty())
     std::cout << " (" << addDscr << ", reason: " << reason << ")";
    else
     std::cout << " (" << addDscr << ")";
   }

  // In DEBUG_MODE, print the source file name and line number at which the exception was thrown
#ifdef DEBUG_MODE
  std::cout << " (file: \"" << srcFile << "\", line: " << lineNumber << ")";
#endif

  // Print the error logging trailer
  std::cout << RESET << std::endl;

  // For scode of FATAL severity, call the application's shutdown handler
  if(sev == FATAL)
   terminate(EXIT_FAILURE);
 }


/**
 * @brief      scodeException default handler, passing all information in the exception
 *             to the SafeCloud application default error handler handleScodeError():\n
 * @param excp The handled scodeException object
 */
void handleScodeException(const sCodeException& excp)
 {
#ifdef DEBUG_MODE
  handleScodeError(excp.scode, excp.addDscr, excp.reason, excp.srcFile, excp.lineNumber);
#else
  handleScodeError(excp.scode,excp.addDscr,excp.reason);
#endif
  // NOTE: Exception objects are automatically destroyed after handling (matching
  //       catch{} clause), and so do not require to be manually deallocated
}