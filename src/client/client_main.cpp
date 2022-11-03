/* SafeCloud Client Application Main Driver */

/* ================================== INCLUDES ================================== */

// System Headers
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <cstring>

// SafeCloud Headers
#include "defaults.h"
#include "errCodes/execErrCodes/execErrCodes.h"
#include "Client/Client.h"

/* ========================== GLOBAL STATIC VARIABLES ========================== */
Client* cli;  // The singleton SafeCloud Client object

/* =========================== FUNCTIONS DEFINITIONS =========================== */

/* ------------------- SafeCloud Client Shutdown Management ------------------- */

/**
 * @brief            SafeCloud Client Application termination handler, deleting
 *                   if existing the Client object and terminating the application
 * @param exitStatus The exit status to be returned to the OS via the exit() function
 */
void terminate(int exitStatus)
 {
  // Delete, if present, the SafeCloud Client object
  delete cli;

  // Print the SafeCloud Client application closing message
  std::cout << "\nSafeCloud Client Terminated" << std::endl;

  // Exit to the OS with the specified status
  exit(exitStatus);
 }


/**
 * @brief SafeCloud Client application OS signals callback handler, which,
 *        upon receiving any of the OS signals handled by the application
 *        (SIGINT, SIGTERM, SIGQUIT), if the client object does not exist
 *        yet or it can be terminated directly terminates the application,
 *        otherwise the client object is instructed to terminate as soon
 *        as its pending requests will have been served
 * @param signum The OS signal identifier (unused)
 */
void OSSignalsCallback(__attribute__((unused)) int signum)
 {
  // Whether the SafeCloud client application can be terminated directly
  bool directShutdown;

  // The status by which the SafeCloud client
  // application should directly exit to the OS with
  int exitStatus;

  LOG_INFO("Shutdown signal received, performing cleanup operations...")

  try
   {
    // If the client object does not exist yet or it can
    // be terminated directly, set that the SafeCloud
    // Client application can be terminated directly
    directShutdown = (cli == nullptr || cli->shutdownSignalHandler());

    // As no error has occurred, if existing the SafeCloud client
    // application should do so with the 'EXIT_SUCCESS' status
    exitStatus = EXIT_SUCCESS;
   }
  catch(execErrExcp& cliExecExcp)
   {
    // Handle the execution exception
    handleExecErrException(cliExecExcp);

    // As an execution exception would cause the client object to
    // disconnect from the SafeCloud server, it can be terminated
    // directly, in this case with the 'EXIT_FAILURE' state
    directShutdown = true;
    exitStatus = EXIT_FAILURE;
   }

  // If the SafeCloud client application can be terminated
  // directly, do so with the appropriate exit status
  if(directShutdown)
   terminate(exitStatus);
}


/* ------------------------ Client Object Initialization ------------------------ */

/**
 * @brief         Attempts to initialize the SafeCloud Client object by passing
 *                it the IP and port of the SafeCloud server to connect to
 * @param srvIP   The IP address as a string of the SafeCloud server to connect to
 * @param srvPort The port of the SafeCloud server to connect to
 */
void clientInit(char* srvIP,uint16_t& srvPort)
 {
  // Attempt to initialize the client object by
  // passing the server connection parameters
  try
   { cli = new Client(srvIP,srvPort); }
  catch(execErrExcp& exeErrExcp)
   {
    // If the exception is relative to an invalid srvIP or srvPort passed
    // via command-line arguments, "gently" inform the user of their
    // allowed values without recurring to the built-in logging macros
    if(exeErrExcp.exErrcode == ERR_SRV_ADDR_INVALID)
     std::cerr << "\nPlease specify a valid IPv4 address as value "
                  "for the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
    else
     if(exeErrExcp.exErrcode == ERR_SRV_PORT_INVALID)
      std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN)
                << " for the '-p' option\n" << std::endl;

     // Otherwise the exception is relative to a fatal error associated
     // with the client building its X.509 certificates store, which
     // should be handled by the general handleExecErrException()
     // function (which most likely will terminate the execution)
     else
      handleExecErrException(exeErrExcp);

    // If no fatal error occurred, delete the Client object and exit silently
    delete(cli);
    exit(EXIT_FAILURE);
   }
 }


/* ------------------- Command-Line Input Parameters Parsing ------------------- */

/**
 * @brief Prints a summary of the program's valid input
 *        options and values (parseCmdArgs() utility function)
 */
void printProgramUsageGuidelines()
 {
  std::cerr << "\nUsage:" << std::endl;
  std::cerr << "----- " << std::endl;
  std::cerr << "./client                   -> Connect to the SafeCloud server "
               "with default IP (" << SRV_DEFAULT_IP << ") and port ("
               << SRV_DEFAULT_PORT << ")" << std::endl;
  std::cerr << "./client [-a IP] [-p PORT] -> Connect to the SafeCloud server "
               "with a custom IPv4 address and/or a custom port PORT >= "
               << std::to_string(SRV_PORT_MIN) << std::endl;
  std::cerr << std::endl;
 }


/**
  * @brief Parses the command-line arguments with which the application was called and:\n\n
  *           1) If unknown options and/or values were passed, a help summary of the
  *              expected arguments' syntax is printed and the program is terminated\n\n
  *           2) Values of valid input options override the default ones defined in
  *              "defaults.h" (with validity checks remanded to the Client's constructor)\n\n
  *           3) The resulting options' values are written in
  *              the reference variables provided by the caller
  * @param argc    The number of command-line input arguments
  * @param argv    The array of command-line input arguments
  * @param srvIP   The resulting SafeCloud server IP address to connect to as a string
  * @param srvPort The resulting SafeCloud server port to connect to
  */
void parseCmdArgs(int argc, char** argv, char* srvIP, uint16_t& srvPort)
 {
  // The candidate IP and port of the SafeCloud server to connect to
  char     _srvIP[16] = SRV_DEFAULT_IP;
  uint16_t _srvPort   = SRV_DEFAULT_PORT;

  // The current command-line option parsed by the getOpt() function
  int      opt;

  // Read all command-line arguments via the getOpt() function
  while((opt = getopt(argc, argv, ":a:p:h")) != -1)
   switch(opt)
    {
     // Help option
     case 'h':
      printProgramUsageGuidelines();
     exit(EXIT_SUCCESS);
     // break

     // Server IP option + its value
     case 'a':
      strncpy(_srvIP, optarg, 15);
     break;

     // Server Port option + its value
     case 'p':

      /*
       * Cast the parameter's value to integer
       *
       * NOTE: If the parameter's value cannot be cast to an integer
       *       the atoi() returns 0, which is later accounted in
       *       asserting that it must be srvPort >= SRV_PORT_MIN > 0
       */
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err34-c"
      _srvPort = atoi(optarg);
#pragma clang diagnostic pop
     break;

     // Missing IP or Port value
     case ':':
      if(optopt == 'a')   // Missing IP value
       std::cerr << "\nPlease specify a valid IPv4 address as value for "
                    "the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
      else
       if(optopt == 'p')  // Missing Port value
        std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN)
                  << " for the '-p' option\n" << std::endl;
       else
        LOG_CRITICAL("Missing value for unknown parameter: "
                     "\'" + std::to_string(optopt) + "\'")
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

  // Copy the UNVALIDATED temporary option's values
  // into the references provided by the caller
  strncpy(srvIP, _srvIP, 15);
  srvPort = _srvPort;
 }


/* ------------------ SafeCloud Client Application Entrypoint ------------------ */

/**
 * @brief       The SafeCloud client application entry point
 * @param argc  The number of command-line input arguments
 * @param argv  The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  // The IP address and port of the SafeCloud server to connect to
  char srvIP[16];
  uint16_t srvPort;

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, OSSignalsCallback);
  signal(SIGTERM, OSSignalsCallback);
  signal(SIGQUIT, OSSignalsCallback);

  // Determine the IP and port of the SafeCloud server the client
  // application should connect to by parsing the command-line arguments
  parseCmdArgs(argc,argv,srvIP,srvPort);

  // Attempt to initialize the SafeCloud Client object by passing
  // it the IP and port of the SafeCloud server to connect to
  clientInit(srvIP,srvPort);

  // Start the SafeCloud Client
  try
   { cli->start(); }
  catch(execErrExcp& exeErrExcp)
   {
    // If an error occurred in the client's execution,
    // handle it and terminate the application
    handleExecErrException(exeErrExcp);
    terminate(EXIT_FAILURE);
   }

  // If the SafeCloud client closed gracefully, terminate the application
  terminate(EXIT_SUCCESS);
 }