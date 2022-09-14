/* SafeCloud user object implementation */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "user.h"
#include "safecloud/scode.h"


/* ============================== GLOBAL VARIABLES ============================== */
extern clientMap cliMap;  // Map of connected clients (server_main.cpp)

// Constructor
//
// NOTE: the const char* ip requires an explicit post-initialization for initializer lists shenanigans
//


/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* Constructor */
user::user(int csk,const char* ip, int port, char* name, int session_key) : client (csk,ip,port), _name(), _session_key(session_key)
 { strcpy(_name,name); }

// Destructor TODO
user::~user()
 {}

/**
 * @brief  Reads data from the connection socket associated with the user and performs the appropriate actions
 * @return An indication of the action to be performed by the server network manager on this client object:
 *  @retval KEEP_CONN  - Keep the connection socket open  (no action required)
 *  @retval CLOSE_CONN - Delete the client object and close its connection socket
 */
postAction user::readData()
 {
 /*
  * TODO: This is just a placeholder implementation (in the final application the client just performs the STSM protocol(
  */

 /* ---------------------- Local Variables ---------------------- */
 char buf[1024];
 char hello[] = "Hello from server\0";
 char srvError[] = "Server Error\0";
 char bye[] = "bye\0";

 ssize_t recvBytes;      // Number of bytes read from the connection socket
 clientMapIt cliIt;      // Used for iterating in the map of connected clients
 client* cli;            // Pointer to the client object having received input data
 int shared_secret = 20;
 int session_key = 10;
 char userName[30];

 /* ------------------------ Method Body ------------------------ */

 // Read up to a predefined amount of bytes from the socket
 // TODO: check if dynamic Vector<byte> allocation is a good idea
 //
 recvBytes = recv(_csk, buf, 1023, 0);

 // If the recv returned "-1" an error occurred, and the client connection must be closed
 if(recvBytes == -1)
  {
  // If the client disconnected abruptly, it is not a server error
  if(errno == ECONNRESET)
   LOG_CODE_DSCR_INFO(ERR_USR_ECONNRESET,"(\"" + string(_name) + "\"")

   // Otherwise it is considered, in the broader sense, a server error
  else
   LOG_CODE_DSCR_ERROR(ERR_CSK_RECV_FAILED,"user \"" + string(_name) + "\"," + strerror(errno))

  // Close the client connection
  return CLOSE_CONN;
  }
 else

  // Otherwise if the recv returned "0", the client orderly closed the connection (which must also be closed on this side)
  if(recvBytes == 0)
   {
    LOG_DEBUG("User \"" + string(_name) + "\" has orderly disconnected")
    return CLOSE_CONN;
   }

 // ----------------- At this point recvBytes > 0, which can be processed -------------------

 // Safety
 buf[recvBytes] = '\0';

 // Otherwise, if the client requests to close the connection
 if(!strcmp(buf, "close"))
  {
   // Log
   cout << "User \"" << _name << "\" disconnected" << endl;

   // Inform that the client object and its connection socket should be deleted
   return CLOSE_CONN;
  }

 // Otherwise it is just a random message
 else
  {
   // Echo on terminal
   cout << "\"" << _name <<  "\" says: \"" << buf << "\"" << endl;

   // Reply a predefined message
   send(_csk, (const void*)hello, sizeof(hello), 0);

   // Inform that the client object and connection should be maintained
   return KEEP_CONN;
  }
 } // readData() method