/* SafeCloud guest object implementation */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "guest.h"
#include "user.h"
#include "safecloud/scode.h"

/* ============================== GLOBAL VARIABLES ============================== */
extern clientMap cliMap;  // Map of connected clients (server_main.cpp)


/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* Constructor (same of the client interface) */
guest::guest(int csk,const char* ip, int port) : client (csk,ip,port)
 {}

// Destructor TODO
guest::~guest()
 {}

/**
 * @brief  Reads data from the connection socket associated with the guest and performs the appropriate actions
 * @return An indication of the action to be performed by the server network manager on this client object:
 *  @retval KEEP_CONN  - Keep the connection socket open  (no action required)
 *  @retval DELETE_OBJ - Delete the current client object (returned when a Guest logs in as a User)
 *  @retval CLOSE_CONN - Delete the client object and close its connection socket
 */
postAction guest::readData()
 {
  /*
   * TODO: This is just a placeholder implementation (in the final application the guest just performs the STSM protocol)
   */

  /* ---------------------- Local Variables ---------------------- */
  char buf[1024];
  char hello[] = "Hello from server";
  char login_fail[] = "Login Failed";
  char login_success[] = "Login Success";
  char srvError[] = "Server Error";
  char bye[] = "bye";

  ssize_t recvBytes;       // Number of bytes read from the connection socket
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

  // If the recv returned "-1" an error occurred, and the guest connection must be closed
  if(recvBytes == -1)
   {
    // If the guest disconnected abruptly, it is not a server error
    if(errno == ECONNRESET)
     LOG_CODE_DSCR_INFO(ERR_GST_ECONNRESET,"(csk = " + to_string(_csk))

    // Otherwise it is considered, in the broader sense, a server error
    else
     LOG_CODE_DSCR_ERROR(ERR_CSK_RECV_FAILED,"guest with csk = " + to_string(_csk) + "," + strerror(errno))

    // Close the guest connection
    return CLOSE_CONN;
   }
  else

   // Otherwise if the recv returned "0", the guest orderly closed the connection (which must also be closed on this side)
   if(recvBytes == 0)
    {
     LOG_DEBUG("Guest with csk '" + to_string(_csk) + "' has orderly disconnected")
     return CLOSE_CONN;
    }

  // ----------------- At this point recvBytes > 0, which can be processed -------------------

  // Safety
  buf[recvBytes] = '\0';

  // If the client "logged in"
  if(!strcmp(buf,"login"))
   {
    // Retrieve the entry associated with the guest in the connected client's map
    cliIt = cliMap.find(_csk);

    // If the entry was not found (which should NEVER happen)
    if(cliIt == cliMap.end())
     {
      LOG_CRITICAL("Missing guest entry of connection socket (" + to_string(_csk) + ") from the connected clients' map, login failed")

      // Inform the guest of the unrecoverable server-side error, and so that he should attempt to re-establish a connection
      send(_csk, (const void*)srvError, sizeof(srvError), 0);

      // Inform that the guest object and its connection socket should be deleted
      return CLOSE_CONN;
     }

    // Otherwise if the client object was found
    else
     {
      sprintf(userName, "Alice%d", _csk);

      // Create and initialize a new user object
      user* newUser = new user(_csk, _ip, _port, userName, session_key);

      // Update the guest entry in the connected clients' map so to point to the newly created user object
      cliIt->second = newUser;

      // Inform the client that the login was successful
      send(_csk, (const void*)login_success, sizeof(login_success), 0);

      // Log
      LOG_INFO("Guest logged in as " + string(userName))

      // Inform that the guest object should be deleted
      return DELETE_OBJ;
     }
   } // if(!strcmp(buf,"login"))

  else

   // Otherwise, if the guest requests to close the connection
   if(!strcmp(buf, "close"))
    {
     // Log
     cout << "Guest with connection socket \"" << to_string(_csk) << "\" disconnected" << endl;

     // Inform that the guest object and its connection socket should be deleted
     return CLOSE_CONN;
    }

   // Otherwise it is just a random message
   else
    {
     // Echo on terminal
     cout << "Guest with connection socket \"" << to_string(_csk) << "\" says: \"" << buf << "\"" << endl;

     // Reply a predefined message
     send(_csk, (const void*)hello, sizeof(hello), 0);

     // Inform that the guest object and connection should be maintained
     return KEEP_CONN;
    }
 } // readData() method