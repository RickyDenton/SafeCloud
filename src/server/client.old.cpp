/* SafeCloud guest object implementation */


/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "client_old.h"
#include "errlog.h"
#include "utils.h"

using namespace std;


/* ============================= UTILITY FUNCTIONS ============================= */

/**
 * @brief          Reads data from the client's connection socket into the specified buffer
 *                 and returns whether valid application data was successfully read (recvSize > 0)
 * @param buf      The buffer where to put the data read from the socket
 * @param bufSize  The maximum data to be read from the socket (the buffer's size)
 * @param recvSize The reference where to write the number of bytes read from the socket
 * @return         'true' if valid application data was read from the socket (recvSize > 0) or 'false' otherwise
 */
bool client_old::recvCheck(char* buf, size_t bufSize, ssize_t& recvSize)
 {
  // Attempt to read data from the client's connection socket
  recvSize = recv(_csk, buf, bufSize - 1, 0);

  LOG_DEBUG(string(_name) + " recv() returned " + recvSize)

  // Depending on the recv() return:
  switch(recvSize)
   {
   // Generic Error
   case -1:

   // Log the error
   LOG_CODE_DSCR_ERROR(ERR_CSK_RECV_FAILED,string(_name) + ", strerror(errno)")

   // Inform that the recv() contents are not valid
   // and that the client connection should be aborted
   return false;


   // The client orderly closed the connection
  case 0:

   // TODO: check, possibly merge with the previous case
   // Log that the client has orderly disconnected
   LOG_WARNING(string(_name) + " has orderly disconnected")

   // Inform that the recv() contents are not valid
   // and that the client connection should be aborted
   return false;

   // recvSize > 0, valid data was read
  default:

   // Add the string termination character at the end of the data for safety purposes
   // TODO: This won't be necessary
   buf[recvSize] = '\0';

   // Inform that the recv() contents are valid
   return true;
  }
 }


/* ======================== CLASS METHODS IMPLEMENTATION ======================== */

/* ------------------------ Constructors and Destructor ------------------------ */

/**
 * @brief      Client object constructor
 * @param csk  The client's connection socket
 * @param ip   The client's IP address
 * @param port The client's port
 * @note Arrays must be initialized manually as ISO C++ forbids doing so via initialization lists
 */
client_old::client_old(int csk, const char* ip, int port) : _cliType(GUEST), _csk(csk), _ip(), _port(port), _name(), _skey(0), _iv(0)
 {
  sprintf(_ip,"%15s",ip);         // Client's IP address
  sprintf(_name,"Guest%d",_csk);  // Client's name
 }

/**
 * @brief Client object destructor, which safely deletes its sensible attributes
 */
client_old::~client_old()
 {
  safeFree(this,sizeof(client_old));
 }


/* ------------------------------- Other Methods ------------------------------- */

/**
 * @brief Attempts to read data destined to the client from its connection socket
 *        and performs the appropriate actions depending on its cliType and state
 * @return 'true' if the client connection should be maintained or 'false' otherwise
 */
bool client_old::recvData()
 {

  /* ---------------------- Local Variables ---------------------- */
  char cliMsg[1024];
  char hello[] = "Hello from server";
  char login_success[] = "Login successful";

  ssize_t recvSize;  // Number of bytes read from the connection socket

  /* ------------------------ Method Body ------------------------ */

  // Attempt to read data from the client's connection socket, checking for errors

  if(!recvCheck(cliMsg, sizeof(cliMsg), recvSize))
   {
    // If an error occurred the client connection must be closed
    return false;
   }

  // Otherwise parse the valid application data
  // TODO: This should be implemented via a switch with a string <-> enum mapping

  // If the client disconnected, return that its connection must be closed
  //
  // NOTE: The client disconnection log is performed in the server_loop in the disconnectClient() function
  //
  if(!strcmp(cliMsg, "close"))
   return false;

  // If the client "logged in"
  if(!strcmp(cliMsg, "login"))
   {
    // Update the client's type to USER
    _cliType = USER;

    // Set the user's "name"
    sprintf(_name, "Alice%d", _csk);

    // Inform the user that the login was successful
    send(_csk, (const void*)login_success, sizeof(login_success), 0);

    // Log that the user has logged in
    LOG_INFO("\"Guest" + to_string(_csk) + "\" has logged in as \"Alice" + to_string(_csk) + "\"")

    // Return that the client connection must be maintained
    return true;
   }

  // Otherwise, it is just a random message

  // Echo the client message
  cout << _name << " says \"" << cliMsg << "\"" << endl;

  // Reply a predefined message
  send(_csk, (const void*)hello, sizeof(hello), 0);

  // Return that the client connection must be maintained
  return true;
 }


/**
 * @brief Returns the client's name
 * @return The client's name
 */
char* client_old::getName()
 { return _name; }