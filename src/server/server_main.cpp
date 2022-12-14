/* SafeCloud Server Application Main Driver */

/* ================================== INCLUDES ================================== */

// System Headers
#include <signal.h>
#include <unistd.h>

// SafeCloud Headers
#include "errCodes/execErrCodes/execErrCodes.h"
#include "Server/Server.h"

/* ========================== GLOBAL STATIC VARIABLES ========================== */
Server* srv;  // The singleton SafeCloud Server object

/* =========================== FUNCTIONS DEFINITIONS =========================== */

/* ------------------- SafeCloud Server Shutdown Management ------------------- */

/**
 * @brief            SafeCloud Server Application termination handler, deleting
 *                   if existing the Server object and terminating the application
 * @param exitStatus The exit status to be returned to the OS via the exit() function
 */
void terminate(int exitStatus)
 {
  // Delete, if present, the SafeCloud Server object
  delete srv;

  // Print the SafeCloud Server application closing message
  std::cout << "\nSafeCloud Server Terminated" << std::endl;

  // Exit to the OS with the specified status
  exit(exitStatus);
 }


/**
 * @brief SafeCloud Server application OS signals callback handler, which,
 *        upon receiving any of the OS signals handled by the application
 *        (SIGINT, SIGTERM, SIGQUIT), if the server object does not exist
 *        yet or it can be terminated directly terminates the application,
 *        otherwise the server object is instructed to terminate as soon
 *        as all its pending client requests will have been served
 * @param signum The OS signal identifier (unused)
 */
void OSSignalsCallback(__attribute__((unused)) int signum)
 {
  LOG_INFO("Shutdown signal received, performing cleanup operations...")

  // If the server object does not exist yet or it can be terminated directly,
  // terminate the SafeCloud Server application with an 'EXIT_SUCCESS' status
  if(srv == nullptr || srv->shutdownSignalHandler())
   terminate(EXIT_SUCCESS);
 }


/* ------------------------ Server Object Initialization ------------------------ */

/**
 * @brief         Attempts to initialize the SafeCloud Server
 *                object by passing it the OS port it must bind on
 * @param srvPort The port the SafeCloud server must bind on
 */
void serverInit(uint16_t& srvPort)
 {
  // Attempt to initialize the client object by
  // passing the server connection parameters
  try
   { srv = new Server(srvPort); }
  catch(execErrExcp& excp)
   {
    // If the exception is relative to an invalid srvIP passed via
    // command-line arguments, "gently" inform the user of the allowed
    // port values without recurring to the built-in logging macros
    if(excp.exErrcode == ERR_SRV_PORT_INVALID)
     std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN)
               << " for the '-p' option\n" << std::endl;

     // All other exceptions should be handled by the general
     // handleExecErrException() function (which, being all
     // of FATAL severity, will terminate the execution)
    else
     handleExecErrException(excp);

    // If no fatal error occurred, delete the Server object and exit silently
    delete(srv);
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
  std::cerr << "./server           -> Bind the server to the default port ("
            << SRV_DEFAULT_PORT << ")" << std::endl;
  std::cerr << "./server [-p PORT] -> Bind the server to the custom PORT >= "
            << std::to_string(SRV_PORT_MIN) << std::endl;
  std::cerr << std::endl;
 }


/**
 * @brief Parses the command-line arguments with which the application was called and:\n\n
 *           1) If unknown options and/or values were passed, a help summary of the
 *              expected arguments' syntax is printed and the program is terminated\n\n
 *           2) Values of valid input options override the default ones defined in
 *              "defaults.h" (with validity checks remanded to the Server's constructor)\n\n
 *           3) The resulting options' values are written in
 *              the reference variables provided by the caller
 * @param argc    The number of command-line input arguments
 * @param argv    The array of command-line input arguments
 * @param srvPort The resulting port the SafeCloud server must bind to
 */
void parseCmdArgs(int argc, char** argv, uint16_t& srvPort)
 {
  // The candidate port the SafeCloud server must bind to
  uint16_t _srvPort = SRV_DEFAULT_PORT;

  // The current command-line option parsed by the getOpt() function
  int opt;

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

     // Server Port option WITHOUT value
     case ':':
      std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN)
                << " for the '-p' option\n" << std::endl;
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
  srvPort = _srvPort;
 }


/* ------------------ SafeCloud Server Application Entrypoint ------------------ */

/**
 * @brief      The SafeCloud server application entry point
 * @param argc The number of command-line input arguments
 * @param argv The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  // The OS port the SafeCloud server must bind on
  uint16_t srvPort;

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, OSSignalsCallback);
  signal(SIGTERM, OSSignalsCallback);
  signal(SIGQUIT, OSSignalsCallback);

  // Determine the Port the SafeCloud server must
  // bind to by parsing the command-line arguments
  parseCmdArgs(argc, argv, srvPort);

  // Attempt to initialize the SafeCloud Server
  // object by passing the OS port it must bind on
  serverInit(srvPort);

  // Start the SafeCloud server
  try
   { srv->start(); }
  catch(execErrExcp& excp)
   {
    // If an error occurred in the server's execution,
    // handle it and terminate the application
    handleExecErrException(excp);
    terminate(EXIT_FAILURE);
   }

  // If the SafeCloud server terminated
  // gracefully, terminate the application
  terminate(EXIT_SUCCESS);
 }