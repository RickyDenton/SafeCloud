/* SafeCloud Server Main Loop */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"

using namespace std;

/* ============================ FORWARD DECLARATIONS ============================ */

/*
// The file descriptor of the server's listening socket
extern int lsk;

// An unordered map used for associating connection sockets' file descriptors to their client objects
//
// NOTE: connMap.size() -> Number of connected clients (whether guests or users)
//
extern  clientMap connMap;

// Closes all client connections, the listening socket and the server application
void serverShutdown(int exitStatus);


*/
/* ============================== GLOBAL VARIABLES ============================== *//*


// The file descriptors set of open sockets (listening socket + connection sockets)
static fd_set skSet;

// The maximum socket file descriptor value (select() optimization purposes)
*/
/*
 * NOTE: This value may refer to a socket that is no longer open (see the disconnectClient() note)
 *//*

static int skMax;


*/
/* ============================ FUNCTIONS DEFINITIONS ============================ *//*


*/
/**
 * @brief       Closes a client's connection socket and remove its associated entry from the connected clients' map
 * @param cliIt The iterator to the client's entry in the connected clients' map
 * @param skSet The file descriptors set of open sockets
 *//*

void disconnectClient(connMapIt cliIt)
 {
 // Attempt to close the client connection socket
 if(cliIt->first > 0)
  {
  if(close(cliIt->first) != 0)
   LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))
  }
 else
  LOG_CRITICAL("Found a connection socket with negative value in the connected clients map!" + to_string(cliIt->first))

 // Remove the client connection socket from the set of file descriptors of open sockets
 FD_CLR(cliIt->first, &skSet);

 */
/* NOTE: If the disconnected client connection socket was the one of maximum value among
  *       all open sockets, the maximum among all remaining sockets should be determined so
  *       to update the "skMax" variable for select() optimization purposes, even if, since
  *       searching the maximum key in an unordered_map is inefficient and adopting an
  *       ordered map (map) would degrade the performance of all other operations, as an
  *       implementation choice the "skMax" value is NOT updated upon client disconnection
  *
  *//*


 // Log the client's disconnection
 LOG_INFO(string(cliIt->second->getName()) + " has disconnected")

 // Remove the client entry from the connected clients' map
 connMap.erase(cliIt);

 // Delete the client object
 delete cliIt->second;

 LOG_DEBUG("Number of connected clients: " + to_string(connMap.size()))
 }


*/
/**
 * @brief Accept an incoming guest connection, creating its client object and entry in the connected clients' map
 *//*

void newGuest()
 {
  */
/* -------------------------- Local Variables -------------------------- *//*

  static unsigned int guestAddrLen = sizeof(sockaddr_in);  // The (static) size of a sockaddr_in structure

  struct sockaddr_in guestAddr{}; // The guest socket type, IP and Port
  char guestIP[16];               // The guest IP address
  int guestPort;                  // The guest port
  int csk = -1;                   // The guest connection socket
  pair<connMapIt,bool> empRet;     // Used to check whether the guest was successfully added to the connected clients' map
  client_old* cli;                    // Client object pointer

  */
/* --------------------------- Function Body --------------------------- *//*


  // Attempt to accept the incoming guest connection, obtaining
  // the file descriptor of the resulting connection socket
  csk = accept(lsk, (struct sockaddr*)&guestAddr, &guestAddrLen);

  // If the guest connection could not be
  // accepted (!), log the error and return
  if(csk == -1)
   {
    LOG_CODE_DSCR_CRITICAL(ERR_CSK_ACCEPT_FAILED, strerror(errno))
    return;
   }

  // Retrieve the new guest's IP and Port
  inet_ntop(AF_INET, &guestAddr.sin_addr.s_addr, guestIP, INET_ADDRSTRLEN);
  guestPort = ntohs(guestAddr.sin_port);

  // Ensure that the maximum number of client connections has not been reached
  */
/*
   * NOTE: This constraint is due to the fact that the select() allows to monitor up to FD_SETSIZE
   *       = 1024 file descriptors, with the listening socket that should also be accounted for
   *//*

  if(connMap.size() == SRV_MAX_CONN)
   {
    // Inform the new guest that the server cannot accept further client connections
    // TODO: Implement in a SafeCloud Message

    // Log the error and return
    LOG_CODE_DSCR_WARNING(ERR_CSK_MAX_CONN,string(guestIP) + to_string(guestPort))
    return;
   }

  // Initialize the guest's Client object
  cli = new client_old(csk, guestIP, guestPort);

  // Create the guest entry in the connected clients' map
  empRet = connMap.emplace(csk, cli);

  // Ensure that the new guest's connection socket was not already present in the connection map
  */
/*
   * NOTE: Trusting the kernel and especially the server implementation this check
   *       is not necessary, but it's still performed for its negligible cost
   *//*

  if(!empRet.second)
   {
    LOG_CRITICAL("The connection socket assigned to a new guest is already present in the connected client's map! (" + to_string(csk) + ")")

    // Close the preexisting client connection and remove its entry from the connected clients'
    // map as an error recovery mechanism (the kernel is probably more right than the application)
    disconnectClient(empRet.first);

    // Re-insert the new guest into the connected client's map (operation that in this case is supposed to always succeed)
    connMap.emplace(csk, cli);
   }

  // Add the connection socket of the new guest to the file descriptors set of
  // open sockets and, if it's the one of maximum value, update the skMax variable
  FD_SET(csk, &skSet);
  skMax = max(skMax, csk);

  // Log the new guest connection and proceed checking the next file descriptor
  LOG_INFO(string(cli->getName()) + " has connected")

  LOG_DEBUG("Number of connected clients: " + to_string(connMap.size()))
 }


*/
/**
 * @brief     Delegates data on a connection socket to its associated client object (recvData()),
 *            and depending on its return, maintains or closes the client connection
 * @param ski The client's connection socket
 *//*

void newClientData(int ski)
 {
  */
/* -------------------------- Local Variables -------------------------- *//*

  connMapIt cliIt;                 // An iterator in the connected clients' map
  client_old* cli;                    // Pointer to a client object
  bool keepConn;                  // An indication on whether a client connection should be maintained ('true') or not

  */
/* --------------------------- Function Body --------------------------- *//*


  // Retrieve the entry in the connected client's map with key "ski"
  cliIt = connMap.find(ski);

  // If the entry was not found (which should NEVER happen)
  if(cliIt == connMap.end())
   {
    LOG_CRITICAL("Missing client map entry of connection socket '" + to_string(ski) + "'")

    // Attempt to close the unmatched connection socket as an error recovery mechanism
    if((ski >= 0) && (close(ski) != 0))
     LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))

    // Return
    return;
   }

  // Retrieve the pointer to the connection socket's client
  cli = cliIt->second;

  // Delegate reading socket data to the client's recvData() method, obtaining an
  // indication of whether its connection should be maintained ('true') or not ('false')
  keepConn = cli->recvData();

  // If the client connection should be closed, do so
  // before proceeding checking the next file descriptor
  if(!keepConn)
   disconnectClient(cliIt);
 }


*/
/*
 * @brief Main and infinite loop of the SafeCloud server application which, by performing asynchronous I/O
 *        via the select() primitive on all open sockets (the listening and the clients' connection sockets):\n
 *        - Accepts incoming guest connections (newGuest())\n
 *        - Delegates data on a connection socket to its associated client object (newClientData())
 *//*

[[noreturn]] void serverLoop()
 {
  */
/* -------------------------- Local Variables -------------------------- *//*

  fd_set skReadSet;   // The file descriptors set of open sockets used for asynchronously reading incoming data
  int rdySks;         // Number of sockets with available input data (select() return)

  */
/* --------------------------- Function Body --------------------------- *//*


  // Initialize the file descriptors sets used for asynchronously reading from sockets via the select()
  FD_ZERO(&skSet);
  FD_ZERO(&skReadSet);

  // Add the listening socket to the file descriptor set of open sockets
  // and initialize the maximum socket file descriptor to its value
  FD_SET(lsk, &skSet);
  skMax = lsk;

  // ------------------------- SERVER MAIN LOOP ------------------------- //
  while(1)
   {
    // Reset the list of sockets to wait input data from to all open sockets
    skReadSet = skSet;

    // Indefinitely await for data to be available on any open socket,
    // obtaining the number of sockets with available input data

    // Wait (indefinitely) for input data to be available on any open
    // socket obtaining the number of sockets with available input data
    rdySks = select(skMax + 1, &skReadSet, NULL, NULL, NULL);

    // If the select() returned a fatal error, the server must be aborted
    if(rdySks == -1)
     {
      LOG_CODE_DSCR_FATAL(ERR_SELECT_FAILED,strerror(errno))
      serverShutdown(EXIT_FAILURE);
     }

    LOG_DEBUG("select() returned " + to_string(rdySks))

    // Browse all sockets file descriptors from 0 to skMax
    for(int ski = 0; ski <= skMax; ski++)

     // If input data is available on socket "ski"
     if(FD_ISSET(ski, &skReadSet))
      {
       // If "ski" is the server's listening socket, a new guest is attempting to connect with the server
       if(ski == lsk)
        newGuest();

       // Otherwise "ski" is a connection socket and so new client data is available
       else
        newClientData(ski);

       // Once the listening or connection socket has been served, decrement the number of sockets with pending input
       // data and, if no other is present, break the "for" loop for restarting from the server main "while(1)" loop
       if(--rdySks == 0)
        break;
      }
   } // Server main "while(1)" loop
 } // EXECUTION SHOULD NEVER REACH HERE*/
