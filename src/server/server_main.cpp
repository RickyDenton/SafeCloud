/* SafeCloud Server main driver */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>

// TCP/IP Libraries
#include <arpa/inet.h>
#include <unordered_map>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"
#include "Server/Server.h"

/* ========================== GLOBAL STATIC VARIABLES ========================== */
Server* srv;  // The singleton Server object

/* ============================ FUNCTIONS DEFINITIONS ============================ */

/* ------------------------- Client Shutdown Management ------------------------- */

/**
 * @brief            Deletes the Server object and terminates the SafeCloud Server application
 * @param exitStatus The exit status to be returned to the OS via the exit() function
 */
void terminate(int exitStatus)
 {
  // Delete the server object
  delete srv;

  // Print the closing message
  std::cout << "\nSafeCloud Server Terminated" << std::endl;

  // Exit with the indicated status
  exit(exitStatus);
 }


/**
 * @brief        Process's OS signals callback handler, which, upon receiving
 *               any of the handled signals (SIGINT, SIGTERM, SIGQUIT):\n
 *                 - If the server object does not exist or it not connected with any client,
 *                   it directly terminates the application by calling the terminate() function\n
 *                 - If the server object is connected with at least one client, it
 *                   is instructed to gracefully close all connections and terminate
 * @param signum The OS signal identifier (unused)
 */
void OSSignalsCallback(__attribute__((unused)) int signum)
 {
  // If the server object does not exist or is not connected with any client, directly terminate the application
  if(srv == nullptr || !srv->isConnected())
   {
    LOG_INFO("Shutdown signal received, performing cleanup operations...")
    terminate(EXIT_SUCCESS);
   }

  // Otherwise instruct the server object to gracefully close all connections and terminate
  else
   {
    LOG_INFO("Shutdown signal received, closing the server's connection...")
    srv->shutdownSignal();
   }
 }


/* ---------------------------- Server Initialization ---------------------------- */

/**
 * @brief         Attempts to initialize the SafeCloud Server object by passing it the OS port it must bind on
 * @param srvPort The port the SafeCloud server must bind on
 */
void serverInit(uint16_t& srvPort)
 {
  // Attempt to initialize the client object by passing the server connection parameters
  try
   { srv = new Server(srvPort); }
  catch(sCodeException& excp)
   {
    // If the exception is relative to an invalid srvIP passed via command-line arguments, "gently"
    // inform the user of the allowed port values without recurring to the built-in logging macros
    if(excp.scode == ERR_SRV_PORT_INVALID)
     std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;

     // All other exceptions should be handled by the general handleScodeException()
     // function (which, being all of FATAL severity, will terminate the execution)
    else
     handleScodeException(excp);

    // If no fatal error occurred, delete the Server object and exit silently
    delete(srv);
    exit(EXIT_FAILURE);
   }
 }


/* ------------------- Command-Line Input Parameters Parsing ------------------- */

/**
 * @brief Prints a summary of the program's valid input options and values (parseCmdArgs() utility function)
 */
void printProgramUsageGuidelines()
 {
  std::cerr << "\nUsage:" << std::endl;
  std::cerr << "----- " << std::endl;
  std::cerr << "./server           -> Bind the server to the default port (" << SRV_DEFAULT_PORT << ")" << std::endl;
  std::cerr << "./server [-p PORT] -> Bind the server to the custom PORT >= " << std::to_string(SRV_PORT_MIN) << std::endl;
  std::cerr << std::endl;
 }


/**
 * @brief         Parses the command-line arguments with which the application was called and:\n
 *                1) If unknown options and/or values were passed, a help summary of the
 *                   expected arguments' syntax is printed and the program is terminated\n
 *                2) Values of valid input options override the default ones defined in
 *                   "defaults.h" (even if NO CHECK ON THEIR VALIDITY IS PERFORMED)\n
 *                3) The resulting options' values are written in
 *                   the reference variables provided by the caller
 * @param argc    The number of command-line input arguments
 * @param argv    The array of command-line input arguments
 * @param srvPort The resulting port the SafeCloud server must bind to
 */
void parseCmdArgs(int argc, char** argv, uint16_t& srvPort)
 {
  uint16_t _srvPort = SRV_DEFAULT_PORT;  // The candidate port the SafeCloud server must bind to
  int opt;                               // The current command-line option parsed by the getOpt() function

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
      //       which is later accounted in asserting that it must be srvPort >= SRV_PORT_MIN > 0
      //
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err34-c"
     _srvPort = atoi(optarg);
#pragma clang diagnostic pop
      break;

     // Server Port option WITHOUT value
     case ':':
      std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;
      exit(EXIT_FAILURE);
      // break;

     // Unsupported option
     case '?':
      std::cerr << "\nUnsupported option: \"" << char(optopt) << "\"" << std::endl;
      printProgramUsageGuidelines();
      exit(EXIT_FAILURE);
      // break;

     // Default (should NEVER happen)
     default:
      LOG_FATAL("Unexpected getOpt() return: \"" + std::to_string(opt) + "\"")
      exit(EXIT_FAILURE);
    }

  // Check for erroneous non-option arguments
  if(optind != argc)
   {
    std::cerr << "\nInvalid arguments: ";
    for(int i = optind; i < argc; i++)
     std::cerr << argv[i] << " ";
    std::cerr << std::endl;

    printProgramUsageGuidelines();
    exit(EXIT_FAILURE);
   }

  // Copy the temporary option's values into the references provided by the caller
  //
  // NOTE: Remember that such values are NOT validated here
  srvPort = _srvPort;
 }


/* -------------------------------- Server Main -------------------------------- */

/**
 * @brief      The SafeCloud server entry point
 * @param argc The number of command-line input arguments
 * @param argv The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  uint16_t srvPort;    // The OS port the SafeCloud server must bind on

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, OSSignalsCallback);
  signal(SIGTERM, OSSignalsCallback);
  signal(SIGQUIT, OSSignalsCallback);

  // Determine the Port the SafeCloud server must bind to by parsing the command-line arguments
  parseCmdArgs(argc, argv, srvPort);

  // Attempt to initialize the SafeCloud Server
  // object by passing the OS port it must bind on
  serverInit(srvPort);

  // Start the SafeCloud server
  try
   { srv->start(); }
  catch(sCodeException& excp)
   {
    // If an error occurred in the server's execution,
    // handle it and terminate the application
    handleScodeException(excp);
    terminate(EXIT_FAILURE);
   }

  // If the SafeCloud server closed gracefully, terminate the application
  terminate(EXIT_SUCCESS);
 }