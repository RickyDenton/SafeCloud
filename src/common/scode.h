#ifndef SAFECLOUD_SCODE_H
#define SAFECLOUD_SCODE_H

/* SafeCloud application status codes definitions and descriptions */

/* ================================== INCLUDES ================================== */
#include <map>


/* ===================== SAFECLOUD STATUS CODES DEFINITIONS ===================== */
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

/* ===================== SAFECLOUD STATUS CODES DESCRIPTIONS ===================== */

// A Map associating status codes of the SafeCloud application to their human-readable string description (used by logging macros)
typedef std::map<scode,const char*> scodeDscrMap;

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
    { ERR_CSK_RECV_FAILED,   "Error in reading data from connection socket" },

    // Unknown
    { ERR_UNKNOWN, "Unknown Error" }
  };


#endif //SAFECLOUD_SCODE_H