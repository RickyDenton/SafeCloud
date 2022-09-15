#ifndef SAFECLOUD_ERRLOG_H
#define SAFECLOUD_ERRLOG_H

/* SafeCloud application error logging macros */

/* ================================== INCLUDES ================================== */
#include <map>
#include "colors.h"
#include "scode.h"

/* ============================ LOGGING UTILITY MACROS ============================ */

// Returns the string description of a status code
#define CODE_DESC(scode) scodeDscr.find(scode)->second

// In DEBUG mode LOG macros also print the name and line of the file where the LOG was called
#ifdef DEBUG
 #define FILE_LINE_DEBUG " (file: \"" << __FILE__ << "\", line: " << to_string(__LINE__) << ")"
#else
 #define FILE_LINE_DEBUG " "
#endif


/* ===================== ERROR CODES LOGGING (FATAL to INFO) ===================== */
#define LOG_CODE_FATAL(scode)                                                       \
 cout << BOLDBRIGHTRED << "<FATAL> " << BRIGHTRED << CODE_DESC(scode) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_CRITICAL(scode)                                                    \
 cout << BOLDBRIGHTRED << "<CRITICAL> " << BRIGHTRED << CODE_DESC(scode) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_ERROR(scode)                                                       \
 cout << BOLDRED << "<ERROR> " << RED << CODE_DESC(scode) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_WARNING(scode)                                                     \
 cout << BOLDYELLOW << "<WARNING> " << YELLOW << CODE_DESC(scode) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_INFO(scode)                                                        \
 cout << "<INFO> " << CODE_DESC(scode) << FILE_LINE_DEBUG << endl;


/* ============== ERROR CODES + DESCRIPTION LOGGING (FATAL to INFO) ============== */
#define LOG_CODE_DSCR_FATAL(scode,errStr)                                           \
 cout << BOLDBRIGHTRED << "<FATAL> " << BRIGHTRED << CODE_DESC(scode) << " (" << (errStr) << ")" << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_DSCR_CRITICAL(scode,errStr)                                        \
 cout << BOLDBRIGHTRED << "<CRITICAL> " << BRIGHTRED << CODE_DESC(scode) << " (" << (errStr) << ")" << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_DSCR_ERROR(scode,errStr)                                           \
 cout << BOLDRED << "<ERROR> " << RED << CODE_DESC(scode) << " (" << (errStr) << ")" << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_DSCR_WARNING(scode,errStr)                                         \
 cout << BOLDYELLOW << "<WARNING> " << YELLOW << CODE_DESC(scode) << " (" << (errStr) << ")" << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CODE_DSCR_INFO(scode,errStr)                                            \
 cout << "<INFO> " << CODE_DESC(scode) << " (" << (errStr) << ")" << FILE_LINE_DEBUG << endl;


/* =================== CUSTOM STRING LOGGING (FATAL to DEBUG) =================== */
#define LOG_FATAL(logStr)                                                          \
 cout << BOLDBRIGHTRED << "<FATAL> " << BRIGHTRED << (logStr) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_CRITICAL(logStr)                                                       \
 cout << BOLDBRIGHTRED << "<CRITICAL> " << BRIGHTRED << (logStr) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_ERROR(logStr)                                                          \
 cout << BOLDRED << "<ERROR> " << RED << (logStr) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_WARNING(logStr)                                                        \
 cout << BOLDYELLOW << "<WARNING> " << YELLOW << (logStr) << FILE_LINE_DEBUG << RESET << endl;

#define LOG_INFO(logStr)                                                           \
 cout << "<INFO> " << (logStr)  << endl;                                            \
 // cout << BOLDBRIGHTWHITE << "<INFO> " << BRIGHTWHITE << #logStr << RESET << endl;

// NOTE: LOG_DEBUG outputs in DEBUG mode only
#ifdef DEBUG
#define LOG_DEBUG(logStr)                                                        \
  cout << BOLDBRIGHTBLACK << "<DEBUG> " << BRIGHTBLACK << (logStr) << RESET << endl;
#else
 #define LOG_DEBUG(logStr) ;
#endif


#endif //SAFECLOUD_ERRLOG_H
