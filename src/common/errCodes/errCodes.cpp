/* SafeCloud Generic Error Codes Definitions */

/* ================================== INCLUDES ================================== */
#include "errCodes.h"

/* ============================ FORWARD DECLARATIONS ============================ */
extern void terminate(int exit_status);   // SafeCloud application shutdown handler


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief Prints to stdout the formatted logging header associated with an
 *        an error code's severity level (handleErrCode() helper function)
 * @param sevLevel The error code's severity level
 */
void printSevLevHeader(errCodeSeverity sevLevel)
 {
  switch(sevLevel)
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
     std::cerr << "<FATAL> UNKNOWN SECURITY LEVEL in printSevLevHeader() (" + std::to_string(sevLevel) + ")" << std::endl;
    terminate(EXIT_FAILURE);
   }
 }


/**
 * @brief            SafeCloud application default error handler, which:\n\n
 *                     1) Logs all information associated with the error, including:\n\n
 *                        1. The severity level of the associated error code\n\n
 *                        2. The human-readable description of the associated error code\n\n
 *                        3. (if available) The additional error description\n\n
 *                        4. (if available) The error reason\n\n
 *                        5. (if DEBUG_MODE) The source file name and line number at which the error has occurred\n\n
 *                     2) For errors codes of FATAL severity, the SafeCloud application is
 *                        terminated by invoking the default shutdown handler (terminate() function)
 * @param errInf     The severity level and human-readable description of the associated error code
 * @param addDsc     The additional error description (optional)
 * @param reason     The error reason (optional)
 * @param srcFile    (DEBUG MODE ONLY) The source file where the error has occurred
 * @param lineNumber (DEBUG MODE ONLY) The line number at which the error has occurred
 */
#ifdef DEBUG_MODE
void handleErrCode(const errCodeInfo errInf, const std::string* addDscr, const std::string* reason, const std::string* srcFile, const unsigned int lineNumber)
#else
void handleErrCode(const errCodeInfo errInf,const std::string* addDscr,const std::string* reason)
#endif
 {
  // Print the formatted logging header associated with the error code's severity level
  printSevLevHeader(errInf.sevLev);

  // Print the human-readable description associated with the error code
  std::cout << errInf.humanDscr;

  // If present, log the error additional description and reason
  if(addDscr != nullptr)
   {
    if(reason != nullptr)
     std::cout << " (" << *addDscr << ", reason: " << *reason << ")";
    else
     std::cout << " (" << *addDscr << ")";
   }

  // In DEBUG_MODE, print the source file name and line number at which the exception was thrown
#ifdef DEBUG_MODE
  std::cout << " (file: \"" << *srcFile << "\", line: " << lineNumber << ")";
#endif

  // Print the error logging trailer
  std::cout << RESET << std::endl;

  // Deallocate the string arguments
  delete addDscr;
  delete reason;
#ifdef DEBUG_MODE
  delete srcFile;
#endif

  // For error codes of FATAL severity, call the SafeCloud application shutdown handler
  if(errInf.sevLev == FATAL)
   terminate(EXIT_FAILURE);
 }