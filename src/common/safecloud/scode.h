#ifndef SAFECLOUD_SCODE_H
#define SAFECLOUD_SCODE_H

/* SafeCloud application logging macros and status codes definitions */

/* ================================== INCLUDES ================================== */
#include <map>
#include "scolors.h"
#include "sdef.h"

using namespace std;

/* ============================ ERROR LOGGING MACROS ============================ */

// Returns the string description of a status code
#define CODE_DESC(scode) scodeDscr.find(scode)->second

// In DEBUG mode LOG macros also print the name and line of the file where the LOG was called
#ifdef DEBUG
 #define FILE_LINE_DEBUG " (file: \"" << __FILE__ << "\", line: " << to_string(__LINE__) << ")"
#else
  #define FILE_LINE_DEBUG " "
#endif

/* --------------------- ERROR CODES LOGGING (FATAL to INFO) --------------------- */
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

/* -------------- ERROR CODES + DESCRIPTION LOGGING (FATAL to INFO) -------------- */
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

/* ------------------- CUSTOM STRING LOGGING (FATAL to DEBUG) ------------------- */
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
 //cout << BOLDBRIGHTWHITE << "<INFO> " << BRIGHTWHITE << #logStr << RESET << endl;

// NOTE: LOG_DEBUG outputs in DEBUG mode only
#ifdef DEBUG
 #define LOG_DEBUG(logStr)                                                        \
  cout << BOLDBRIGHTBLACK << "<DEBUG> " << BRIGHTBLACK << (logStr) << RESET << endl;
#else
 #define LOG_DEBUG(logStr) ;
#endif


/* ============================== TYPE DEFINITIONS ============================== */

// SafeCloud Application Status Codes
enum scode
{
 // Operation Successful
 OK = 0,

 /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

 // Listening Socket
 ERR_LSK_INIT_FAILED,
 ERR_LSK_OPT_FAILED,
 ERR_LSK_BIND_FAILED,
 ERR_LSK_LISTEN_FAILED,
 ERR_LSK_CLOSE_FAILED,

 // Connection Sockets
 ERR_CSK_ACCEPT_FAILED,
 ERR_CSK_MAX_CONN,

 // Clients
 ERR_CLI_CONN_ERROR,

 // Guests
 ERR_GST_ECONNRESET,

 // Users
 ERR_USR_ECONNRESET,

 // Other
 ERR_SELECT_FAILED,



 /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

 // Connection socket
 ERR_CSK_INIT_FAILED,
 ERR_CSK_CONN_FAILED,
 ERR_SRV_ECONNRESET,

 /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

 // Connection Sockets
 ERR_CSK_CLOSE_FAILED,
 ERR_CSK_RECV_FAILED,

 // Unknown error
 ERR_UNKNOWN = -1
};

// A Map associating status codes of the SafeCloud application to their human-readable string description (used by logging macros)
typedef std::map<scode,const char*> scodeDscrMap;


/**
 * @brief A Map associating status codes of the SafeCloud application to
 *        their human-readable string description (used by logging macros)
 */
static const scodeDscrMap scodeDscr =
  {
    // Operation Successful
    { OK, "Operation Successful"},

    /* -------------------------- SERVER-SPECIFIC ERRORS -------------------------- */

    // Listening Socket
    { ERR_LSK_INIT_FAILED,   "Listening Socket Creation Failed" },
    { ERR_LSK_OPT_FAILED,    "Listening Socket Options Setting Failed" },
    { ERR_LSK_BIND_FAILED,   "Listening Socket Binding Failed" },
    { ERR_LSK_LISTEN_FAILED, "Listening Socket Listen Failed" },
    { ERR_LSK_CLOSE_FAILED,  "Listening Socket Closing Failed" },

    // Connection Sockets
    { ERR_CSK_ACCEPT_FAILED, "Connection Socket Accept Failed" },
    { ERR_CSK_MAX_CONN,      "Maximum number of client connections reached, an incoming guest connection has been refused" },

    // Clients
    { ERR_CLI_CONN_ERROR,    "Unrecoverable server-side error in the client connection" },

    // Guests
    { ERR_GST_ECONNRESET,    "Guest abruptly closed the connection" },

    // Users
    { ERR_USR_ECONNRESET,    "User abruptly closed the connection" },

    // Other
    { ERR_SELECT_FAILED,     "Select Failed" },

    /* -------------------------- CLIENT-SPECIFIC ERRORS -------------------------- */

    // Connection Socket
    { ERR_CSK_INIT_FAILED,   "Connection Socket Creation Failed" },
    { ERR_CSK_CONN_FAILED,   "Fatal error in connecting with the server" },
    { ERR_SRV_ECONNRESET,    "Server abruptly closed the connection" },

    /* ----------------------- CLIENT-SERVER COMMON ERRORS ----------------------- */

    // Connection sockets
    { ERR_CSK_CLOSE_FAILED,  "Connection Socket Close Failed" },
    { ERR_CSK_RECV_FAILED,   "Socket Receive Error" },

    // Unknown
    { ERR_UNKNOWN, "Unknown Error" }
  };
#endif //SAFECLOUD_SCODE_H