/* Entry point and server connection manager of the SafeCloud server application */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "safecloud/sdef.h"
#include "safecloud/scode.h"
#include "clients/guest.h"

using namespace std;


/* ============================== GLOBAL VARIABLES ============================== */

// The file descriptor of the server's listening socket
int lsk = -1;

// Maps the file descriptors of open connection sockets to their associated client objects (guests or user objects)
//
// NOTE: cliMap.size() -> Number of connected clients (whether guests or users)
//
clientMap cliMap;


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief            Closes all client connections, the listening socket and the server application
 * @param exitStatus The status to return to the caller via the exit() function
 */
void serverShutdown(int exitStatus)
 {
  // Cycle through the entire connected clients' map, closing their connection sockets "cski" and deallocating their client objects
  for(clientMapIt it = cliMap.begin(); it != cliMap.end(); ++it)
   {
    // TODO: Add a "bye" message

    if(close(it->first) != 0)
     LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED,"csk = " + to_string(it->first) + ", error: " + strerror(errno))
    else
     LOG_DEBUG("Connection socket '" + to_string(it->first) + "' closed")

    delete it->second;
   }

  // If the listening socket is open, close it
  if(lsk != -1)
   {
    if(close(lsk) != 0)
     LOG_CODE_DSCR_CRITICAL(ERR_LSK_CLOSE_FAILED, strerror(errno))
    else
     LOG_DEBUG("Listening socket '" + to_string(lsk) + "' closed")
   }

  // Print the closing message
  cout << "\nSafeCloud Server Terminated" << endl;

  exit(exitStatus);
 }


/**
 * @brief         Process OS signals callback handler
 * @param signum  The received signal's identifier
 * @note          Currently only the SIGINT (ctrl+c), SIGTERM and SIGQUIT signals are handled
 */
void osSignalsCallbackHandler(int signum)
 {
  LOG_INFO("Shutdown signal received, closing the application...")
  serverShutdown(EXIT_SUCCESS);
 }


/**
 * @brief         Initializes the TCP listening socket used by the server application
 * @param srvAddr The reference where to read the desired listening socket type, IP and Port in network representation order
 * @note          The "srvAddr" attributes have already been validated in the parseSrvArgs() function
 */
void init_lsk(struct sockaddr_in& srvAddr)
 {
  int lskOptSet = 1;   // Used for enabling the specified listening socket options

 // Attempt to initialize the listening socket
  lsk = socket(AF_INET, SOCK_STREAM, 0);
  if(lsk == -1)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_INIT_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  LOG_DEBUG("Listening socket file descriptor: " + to_string(lsk))

  // Attempt to set the listening socket's options
  //
  // NOTE: A set of default options is used (check the setsockopt() documentation for more details)
  //
  if(setsockopt(lsk, SOL_SOCKET, SO_REUSEADDR, &lskOptSet, sizeof(lskOptSet)) == -1)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_OPT_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  // Attempt to bind the listening socket on the specified host port
  if(bind(lsk, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) < 0)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_BIND_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  // Attempt to make the server application listen on the listening socket
  if(listen(lsk, SRV_MAX_QUEUED_CONN) < 0)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_LISTEN_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  // Log that the server's listening socket has been successfully initialized
  LOG_INFO("SafeCloud server now listening on all local network interfaces on port " + to_string(ntohs(srvAddr.sin_port)) + ", Awaiting client connections...")
 }


/**
 * @brief Prints a summary of the program's valid input options and values
 */
void printProgramUsageGuidelines()
 {
  cerr << "\nUsage:" << endl;
  cerr << "----- " << endl;
  cerr << "./server           -> Bind the server to the default port (" << SRV_DEFAULT_PORT << ")" << endl;
  cerr << "./server [-p PORT] -> Bind the server to the custom PORT >= " << to_string(SRV_PORT_MIN) << endl;
  cerr << endl;
 }


/**
  * @brief         Parses the command-line input parameters and:\n
  *                1) If unknown options and/or values were passed, a summary of the expected calling syntax is printed and the application is stopped\n
  *                2) Valid input options and values override the default ones defined in sdef.h\n
  *                3) The resulting input options and values are validated and written in the reference and pointers provided by the caller
  * @param argc    The number of command-line input arguments
  * @param argv    The array of command line input arguments
  * @param srvAddr The reference where to write in network representation order the validated Port the SafeCloud server should bind on
  */
void parseSrvArgs(int argc, char** argv, struct sockaddr_in& srvAddr)
 {
  uint16_t srvPort = SRV_DEFAULT_PORT;  // The srvPort candidate value
  int opt;                              // The current command-line option parsed by the getOpt() function

  /* ------------------- Command-Line Input Arguments Parsing -------------------  */

  // Read all command-line arguments via the getOpt() function
  while((opt = getopt(argc, argv, ":p:h")) != -1)
   switch(opt)
    {
     // Help option
     case 'h':
      printProgramUsageGuidelines();
      exit(EXIT_SUCCESS);

     // Server Port option + its value
     case 'p':

      // Cast the parameter's value to integer
      //
      // NOTE: If the parameter's value cannot be cast to an integer the atoi() returns 0,
      //       which is accounted in asserting that it must be srvPort >= SRV_PORT_MIN > 0
      //
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err34-c"
     srvPort = atoi(optarg);
#pragma clang diagnostic pop
      break;

     // Server Port option WITHOUT value
     case ':':
      cerr << "\nPlease specify a PORT >= " << to_string(SRV_PORT_MIN) << " for the '-p' option\n" << endl;
      exit(EXIT_FAILURE);
      // break;

     // Unsupported option
     case '?':
      cerr << "\nUnsupported option: \"" << char(optopt) << "\"" << endl;
      printProgramUsageGuidelines();
      exit(EXIT_FAILURE);
      // break;

     // Default (should NEVER happen)
     default:
      LOG_FATAL("Unexpected getOpt() return: \"" + to_string(opt) + "\"")
      exit(EXIT_FAILURE);
    }

  // Check for erroneous non-option arguments
  if(optind != argc)
   {
    cerr << "\nInvalid arguments: ";
    for(int i = optind; i < argc; i++)
     cerr << argv[i] << " ";

    cerr << endl;
    printProgramUsageGuidelines();
    exit(EXIT_FAILURE);
   }

  /* -------------- Application Parameters Validation and Setting --------------  */

  // If srvPort >= SRV_PORT_MIN, convert it to the network byte order within the "srvAddr" structure
  if(srvPort >= SRV_PORT_MIN)
   {
    LOG_DEBUG("Port to be used for the listening socket: " + to_string(srvPort))
    srvAddr.sin_port = htons(srvPort);
   }
  else // Otherwise, report the error
   {
    cerr << "\nPlease specify a PORT >= " << to_string(SRV_PORT_MIN) << " for the '-p' option\n" << endl;
    exit(EXIT_FAILURE);
   }
 }


/*
 * @brief Main infinite loop of the server application, which through
 *        asynchronous socket I/O on the listening and connection sockets:
 *        1) Accepts guests connection requests
 *        2) Passes incoming data from connected clients to the readData() method of their respective client objects
 *        3) On explicit notification from client objects, closes their associated connection sockets
 */
[[noreturn]] void serverLoop()
 {
  /* ---------------------- Local Variables ---------------------- */

  // Asynchronous Sockets Read
  fd_set skSet;                   // The set of file descriptors of open sockets (listening socket + connection sockets)
  fd_set skReadSet;               // The set of file descriptors of open sockets used for asynchronously reading incoming data via the select()
  int skMax;                      // The maximum file descriptor value among all open sockets (select() optimization purposes)
  int rdySks;                     // Number of sockets with available input data (select() return)

  // Incoming guest connection
  struct sockaddr_in guestAddr{}; // The new guest socket type, IP and Port
  unsigned int guestAddrLen;      // The new guest IP address length
  char guestIP[16];               // The new guest IP address
  int guestPort;                  // The new guest port

  // Connected clients management
  int csk = -1;                    // The file descriptor of a connection socket (multiple purposes)
  clientMapIt cliIt;               // Used for iterating in the map of connected clients
  client* cli;                     // Pointer to the client object having received input data
  pair<clientMapIt,bool> empRet;   // Used to check whether clients were successfully added to the connected clients' map
  postAction action;               // The action to be performed after a client object processed incoming data via the handleData() method

  /* ----------------------- Function Body ----------------------- */

  // Set the size of the guest IP address length
  guestAddrLen = sizeof(guestAddr);

  // Initialize the file descriptor sets used for asynchronously reading from sockets
  FD_ZERO(&skSet);
  FD_ZERO(&skReadSet);

  // Add the listening sockets to the set of file descriptors of open
  // sockets and initialize the maximum file descriptor to its value
  FD_SET(lsk, &skSet);
  skMax = lsk;

  // Server main, infinite loop
  while(1)
   {
    // Reset the list of sockets to wait input data from to all open sockets (listening socket + connection sockets)
    skReadSet = skSet;

   // Wait (indefinitely) for input data to be available on any open
   // socket obtaining the number of sockets with available input data
   //
   // NOTE: The select returning "-1" notifies a (fatal) error
   //
   rdySks = select(skMax + 1, &skReadSet, NULL, NULL, NULL);
   if(rdySks == -1)
    {
     LOG_CODE_DSCR_FATAL(ERR_SELECT_FAILED,strerror(errno))
     serverShutdown(EXIT_FAILURE);
    }

   LOG_DEBUG("select() returned " + to_string(rdySks))

   // Browse all file descriptors (sockets) from 0 to skMax
   for(int i = 0; i <= skMax; i++)

   // If input data is available on socket with file descriptor "i"
   if(FD_ISSET(i,&skReadSet))
    {

     // If it is the listening socket "lsk", a new guest is connecting with the server
     if(i == lsk)
      {
       // Attempt to accept the incoming guest connection, obtaining
       // the file descriptor of its associated connection socket
       csk = accept(lsk, (struct sockaddr*)&guestAddr, &guestAddrLen);

       // If accept() returns an error (!) log it and proceed with the next socket
       if(csk == -1)
        LOG_CODE_DSCR_CRITICAL(ERR_CSK_ACCEPT_FAILED,strerror(errno))
       else
        {
         // Retrieve the new guest's IP and Port
         inet_ntop(AF_INET, &guestAddr.sin_addr.s_addr, guestIP, INET_ADDRSTRLEN);
         guestPort = ntohs(guestAddr.sin_port);

         // Check if the maximum number of client connections has been reached
         /*
          * NOTE: This is necessary due to the select() limitation of monitoring up to
          * FD_SETSIZE = 1024 file descriptors, minus the one required for the listening socket
          */
         if(cliMap.size() == SRV_MAX_CONN)
          {
           // Inform the guest that the server cannot accept further client connections
           // TODO: Implement in a SafeCloud Message

           LOG_CODE_DSCR_WARNING(ERR_CSK_MAX_CONN,string(guestIP) + to_string(guestPort))
          }

         // Otherwise, if the server can accept the guest connection
         else
          {
           // Initialize a Guest object for the guest and insert it in the connected clients map
           empRet = cliMap.emplace(csk,new guest(csk,guestIP,guestPort));

           // TODO: DELETE
           //   // Create the guest a Guest object and insert it in the connected clients map
           //   guest* newGuest = new guest(csk, guestIP, guestPort);
           //  cliMap.insert({csk, newGuest});

           // Double-check that the connection socket associated with
           // the new guest was not present in the connected clients' map
           if(!empRet.second)
            {
             LOG_CRITICAL("Connection socket assigned to new guest is already present in the connected client's map!")

             // Close the newly accepted guest connection as a consistency recovery mechanism
             if(close(csk) != 0)
              LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))
            }

           // If the new guest was successfully added in the connected clients' map
           else
            {
             // Add the guest connection socket to the set of file descriptors of open
             // sockets and if it's the one with maximum value, update the skMax variable
             FD_SET(csk, &skSet);
             skMax = max(skMax, csk);

             // Log the new guest connection
             LOG_INFO("New Guest Connected (IP = " + string(guestIP) + ", Port = " + to_string(guestPort) + ")")

             LOG_DEBUG("Number of connected clients: " + to_string(cliMap.size()))
            }
          }
        }
      } // if (i == lsk)

     // If it not the listening it is the connection socket of a connected client
     else
      {
       // Retrieve the connected clients' map entry associated with the connection socket
       cliIt = cliMap.find(i);

       // If the entry was not found (which should NEVER happen)
       if(cliIt == cliMap.end())
        {
         LOG_CRITICAL("Missing client entry of connection socket (" + to_string(i) +  ") from the connected clients' map")

         // Close the unmatched connection socket
         if(close(i) != 0)
          LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))
        }

       // Otherwise, if the client entry was found
       else
        {
         // Retrieve the pointer to the associated client object
         cli = cliIt->second;

         // Call the client's readData() method for parsing input data,
         // obtaining an indication of the action to be performed afterwards
         action = cli->readData();

         switch(action)
          {
           // Keep the connection socket open  (no action required)
           case KEEP_CONN:
            LOG_DEBUG("readData() of socket " + to_string(i) + " requested to maintain the connection open")
            break;

           // Delete the current client object (returned when a Guest logs in as a User)
           case DELETE_OBJ:
            LOG_DEBUG("readData() of socket " + to_string(i) + " requested to delete the client object")
            delete cli;
            break;

           // Delete the client object and close its connection socket
           case CLOSE_CONN:
            LOG_DEBUG("readData() of socket " + to_string(i) + " requested to close the client connection")

            // Delete the client object
            delete cli;

            // Remove the client entry from the connected clients' map
            cliMap.erase(cliIt);

            // Attempt to close the client connection socket
            if(close(i) != 0)
             LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))

            // Remove the client connection socket from the set of file descriptors of open sockets
            FD_CLR(i, &skSet);

            /* NOTE: If the disconnected client connection socket was the one of maximum value among
             *       all open sockets, the maximum among all remaining sockets should be determined so
             *       to update the "skMax" variable for select() optimization purposes, even if, since
             *       searching for the maximum key in an unordered_map is inefficient and adopting an
             *       ordered map (map) would degrade the performance of all other operations, as an
             *       implementation choice the "skMax" value is NOT updated upon client disconnection
             *
            // If the client's connection socket was the one of maximum value among all open
            // sockets, update the "skMax" variable to the maximum value of the remaining ones
            if(i == skMax)
             {
              // Initialize the new maximum descriptor value
              int newSkMax = -1;   // New maximum descriptor value

              for(cliIt = cliMap.begin(); cliIt != cliMap.end(); ++cliIt)
               newSkMax = max(newSkMax, cliIt->first);

             skMax = newSkMax;
             }
            */

            LOG_INFO("Client with connection socket '" + to_string(csk) + "' disconnected")
            LOG_DEBUG("Connected Clients: " + to_string(cliMap.size()))
            break;

           // Unimplemented postAction (log the error)
           default:
            LOG_CRITICAL("The handleData() of client with connection socket \"" + to_string(i) + "\" returned an undefined postAction (" + to_string(action) + ")")
          } // End postAction
        }  //  End client object found
      }  // End connection socket


    // Once the listening or connection socket has been served, decrement the number of sockets with pending
    // data, and if no other one is present, break the "for" loop to restart from the server main "while(1)" loop
    if(--rdySks == 0)
     break;
    } // if(FD_ISSET(i,&skReadSet))
  } // Server main "while(1)" loop
  // Code should never reach here (error handled in the main() function
 }


/**
 * @brief The SafeCloud client entry point
 * @param argc    The number of command-line input arguments
 * @param argv    The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  /* ---------------------- Local Variables ---------------------- */
  struct sockaddr_in srvAddr{};   // Stores the server socket type, IP and Port in the network representation order

  /* ----------------------- Function Body ----------------------- */

 // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, osSignalsCallbackHandler);
  signal(SIGTERM, osSignalsCallbackHandler);
  signal(SIGQUIT, osSignalsCallbackHandler);

  // Set the server socket type to IPv4 and its IP addressed to be assigned by the host OS
  srvAddr.sin_family = AF_INET;
  srvAddr.sin_addr.s_addr = INADDR_ANY;

  // Parse the command-line arguments to determine the port the host port the server application should bind to
  parseSrvArgs(argc, argv, srvAddr);

  // TODO: Parse Server Files

  // Attempt to initialize the server TCP Listening socket, obtaining its file description in return
  init_lsk(srvAddr);

  // Call the server main loop (which never returns)
  serverLoop();
 }