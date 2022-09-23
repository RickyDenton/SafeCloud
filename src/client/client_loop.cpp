/* SafeCloud Client main loop */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <unistd.h>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "errlog.h"


using namespace std;


/* ============================ FORWARD DECLARATIONS ============================ */
bool askReconnection();   // Utility function asking the client whether to reconnect to the server
void serverConnect();     // Server reconnection attempt

extern int csk;           // Client connection socket with the server


/* ============================ FUNCTIONS DEFINITIONS ============================ */







/*
// Build the client's X.509 certificates store loaded with the CA's certificate and CRL
buildX509Store();

// Client login
login();


// -------------------------------------------------------

// Attempt to establish a connection with the SafeCloud
// server, obtaining the associated connection socket
serverConnect();
*/





















/**
 * @brief          Reads data from the client's connection socket into the specified buffer
 *                 and returns whether valid application data was successfully read (recvSize > 0)
 * @param buf      The buffer where to put the data read from the socket
 * @param bufSize  The maximum data to be read from the socket (the buffer's size)
 * @param recvSize The reference where to write the number of bytes read from the socket
 * @return         'true' if valid application data was read from the socket (recvSize > 0) or 'false' otherwise
 */
//bool recvCheck(char* buf,size_t bufSize,ssize_t& recvSize)
// {
// // Attempt to read data from the client's connection socket
// recvSize = recv(csk, buf, bufSize - 1, 0);
//
// LOG_DEBUG("recv() returned " + recvSize)
//
// // Depending on the recv() return:
// switch(recvSize)
//  {
//  // Generic Error
//  case -1:
//
//   // Log the error
//   LOG_SCODE(ERR_CSK_RECV_FAILED,strerror(errno));
//
//   // Inform that the recv() contents are not valid and
//   // that the current server connection should be aborted
//   return false;
//
//
//   // The server orderly closed the connection
//  case 0:
//
//   // TODO: check, possibly merge with the previous case
//   // Log that the server has orderly disconnected
//   LOG_WARNING("The server has orderly disconnected")
//
//   // Inform that the recv() contents are not valid and
//   // that the current server connection should be aborted
//   return false;
//
//   // recvSize > 0, valid data was read
//  default:
//
//   // Add the string termination character at the end of the data for safety purposes
//   // TODO: This won't be necessary
//   buf[recvSize] = '\0';
//
//   // Inform that the recv() contents are valid
//   return true;
//  }
// }


/**
 * @brief Depending on the user's choice, attempts to reconnect with the SafeCloud server
 * @return 'true' if connection with the SafeCloud server was successfully re-established, or 'false' otherwise
 */
//bool srvConnDown()
// {
//  // Ask the user on whether a reconnection attempt with the server should be performed,
//  if(askReconnection())
//   {
//    // If it should, close the current connection socket
//    if(close(csk) != 0)
//     LOG_SCODE(ERR_CSK_CLOSE_FAILED, strerror(errno));
//    else
//     {
//      LOG_DEBUG("Connection socket '" + to_string(csk) + "' closed")
//      csk = -1;
//     }
//
//    // Attempt to reconnect with the server
//    serverConnect();
//
//    // If the connection was successful, inform the client loop that the execution can continue
//    return true;
//  }
//
//  // Otherwise, inform the client loop that connection was not
//  // re-established (and so that the application must terminate)
//  return false;
// }


// TODO: Placeholder implementation
//void clientLoop()
// {
// char cliMsg[1024];
// char srvAnswer[1024];
// ssize_t recvSize;        // Number of bytes read from the connection socket
//
// while(1)
//  {
//  cout << "Message to send to server: ";
//  cin >> cliMsg;
//
//  send(csk, cliMsg, strlen(cliMsg), 0);
//
//  // If the client wants to close the communication, exit from the clientLoop loop
//  if(!strcmp(cliMsg, "close"))
//   break;
//
//  // Otherwise attempt to read data from the client's connection socket, checking for errors
//  if(recvCheck(srvAnswer,sizeof(srvAnswer),recvSize))
//   {
//    // If no error, just echo the server message
//    cout << "Server answered: \"" << srvAnswer << "\"" << endl;
//   }
//
//   // Otherwise the current server connection must be closed and, as an error recovery
//   // mechanism, ask the client on whether a new connection attempt should be performed
//  else
//   if(!srvConnDown())
//    break;
//  }
// }