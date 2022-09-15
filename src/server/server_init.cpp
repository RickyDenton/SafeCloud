/* Entry point and server connection manager of the SafeCloud server application */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>
#include <unordered_map>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"
#include "client.h"

using namespace std;


/* ============================ FORWARD DECLARATIONS ============================ */
void serverLoop();        // Main server loop


/* ============================== GLOBAL VARIABLES ============================== */

// The file descriptor of the server's listening socket
int lsk = -1;

// An unordered map used for associating connection sockets' file descriptors to their client objects
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
  // Cycle through the entire connected clients' map, closing their connection sockets and deallocating their objects
  for(cliMapIt it = cliMap.begin(); it != cliMap.end(); ++it)
   {
    // TODO: Add a "bye" message?

    // Close the client connection socket
    if(close(it->first) != 0)
     LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED,"csk = " + to_string(it->first) + ", error: " + strerror(errno))
    else
     LOG_DEBUG("Closed connection socket '" + to_string(it->first) + "'")

    // Delete the associated client object
    delete it->second;
   }

 // If the listening socket is open, close it
 if(lsk != -1)
  {
   if(close(lsk) != 0)
    LOG_CODE_DSCR_CRITICAL(ERR_LSK_CLOSE_FAILED, strerror(errno))
   else
    LOG_DEBUG("Closed listening socket '" + to_string(lsk) + "'")
  }

  // Print the server closing message
  cout << "\nSafeCloud Server Terminated" << endl;

  // Exit with the provided status
  exit(exitStatus);
 }


/**
 * @brief         Process OS signals callback handler
 * @param signum  The received signal's identifier
 * @note          Currently only the SIGINT (ctrl+c), SIGTERM and SIGQUIT signals are handled
 */
void osSignalsCallbackHandler(__attribute__((unused)) int signum)
 {
  LOG_INFO("Shutdown signal received, performing cleanup operations...")
  serverShutdown(EXIT_SUCCESS);
 }


/**
 * @brief         Initializes the server's listening socket
 * @param srvAddr The reference where to read the listening socket type, IP and Port in network representation order
 * @note          The "srvAddr" attributes have already been validated in the parseSrvArgs() function
 */
void init_lsk(struct sockaddr_in& srvAddr)
 {
  int lskOptSet = 1;   // Used for enabling the listening socket options

  // Attempt to initialize the server listening socket
  lsk = socket(AF_INET, SOCK_STREAM, 0);
  if(lsk == -1)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_INIT_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  LOG_DEBUG("Created listening socket with file descriptor '" + to_string(lsk) + "'")

  // Attempt to set the listening socket's SO_REUSEADDR option for enabling fast rebinds in case of failures
  if(setsockopt(lsk, SOL_SOCKET, SO_REUSEADDR, &lskOptSet, sizeof(lskOptSet)) == -1)
   LOG_CODE_DSCR_CRITICAL(ERR_LSK_OPT_FAILED,strerror(errno))

  // Attempt to bind the listening socket on the specified host port
  if(bind(lsk, (struct sockaddr*)&srvAddr, sizeof(srvAddr)) < 0)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_BIND_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  // Attempt to make the server listen on the listening socket
  if(listen(lsk, SRV_MAX_QUEUED_CONN) < 0)
   {
    LOG_CODE_DSCR_FATAL(ERR_LSK_LISTEN_FAILED,strerror(errno))
    exit(EXIT_FAILURE);
   }

  // Log that the server's listening socket was initialized successfully
  LOG_INFO("SafeCloud server now listening on all local network interfaces on port " + to_string(ntohs(srvAddr.sin_port)) + ", awaiting client connections...")
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


/**
 * @brief The SafeCloud server entry point
 * @param argc    The number of command-line input arguments
 * @param argv    The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  /* ---------------------- Local Variables ---------------------- */
  struct sockaddr_in srvAddr{};   // The SafeCloud server listening socket type, IP and Port in network representation order

  /* ----------------------- Function Body ----------------------- */

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, osSignalsCallbackHandler);
  signal(SIGTERM, osSignalsCallbackHandler);
  signal(SIGQUIT, osSignalsCallbackHandler);

  // Set the server socket type to IPv4 and to be associated to all host network interfaces (i.e. IP 0.0.0.0)
  srvAddr.sin_family = AF_INET;
  srvAddr.sin_addr.s_addr = INADDR_ANY;

  // Determine the Port the SafeCloud server should bind to by parsing the command-line arguments
  parseSrvArgs(argc, argv, srvAddr);

  // TODO: Parse Server Files

  // Attempt to initialize the server listening socket
  init_lsk(srvAddr);

  // Call the server main loop (which should NEVER return)
  serverLoop();
 }