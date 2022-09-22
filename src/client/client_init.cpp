/* SafeCloud Client entry point and initialization functions */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// OpenSSL Libraries
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <cstring>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"
#include "Client/Client.h"
#include "utils.h"

/* ============================ FORWARD DECLARATIONS ============================ */


/* ========================== GLOBAL STATIC VARIABLES ========================== */

// The singleton Client object
static Client* cli;



/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief            Terminates the SafeCloud Client application
 * @param exitStatus The exit status to be returned to the OS via the exit() function
 */
void terminate(int exitStatus)
 {
  // Delete the client object
  delete cli;

  // Print the closing message
  std::cout << "\nSafeCloud Client Terminated" << std::endl;

  // Exit with the indicated status
  exit(exitStatus);
 }


/**
 * @brief        Process's OS signals callback handler, which, upon receiving
 *               any of the handled signals (SIGINT, SIGTERM, SIGQUIT):\n
 *                 - If the client object does not exist or it has not yet
 *                   connected with the SafeCloud server, it directly terminates
 *                   the application by calling the terminate() function\n
 *                 - If the client object is connected with the SafeCloud server,
 *                   it is informed to close such connection and gracefully
 *                   terminate via the shutdownSignal() method
 * @param signum The OS signal identifier (unused)
 */
void OSSignalsCallback(__attribute__((unused)) int signum)
 {
  // If the client object does not exist or has not connected yet, directly terminate the application
  if(cli == nullptr || !cli->isConnected())
   {
    LOG_INFO("Shutdown signal received, performing cleanup operations...")
    terminate(EXIT_SUCCESS);
   }

  // Otherwise inform the client to close the server connection and gracefully terminate
  else
   {
    LOG_INFO("Shutdown signal received, closing the server's connection...")
    cli->shutdownSignal();
   }
}



/* ================================ CLIENT INITIALIZATION ================================ */

/**
 * @brief Prints the SafeCloud client welcome message
 */
void printWelcomeMessage()
 {
  std::cout << "   _____        __      _____ _                 _ n";
  std::cout << "  / ____|      / _|    / ____| |               | |\n";
  std::cout << " | (___   __ _| |_ ___| |    | | ___  _   _  __| |\n";
  std::cout << "  \\___ \\ / _` |  _/ _ \\ |    | |/ _ \\| | | |/ _` |\n";
  std::cout << "  ____) | (_| | ||  __/ |____| | (_) | |_| | (_| |\n";
  std::cout << " |_____/ \\__,_|_| \\___|\\_____|_|\\___/ \\__,_|\\__,_|" << std::endl;
 }


/**
 * @brief         Attempts to initialize the SafeCloud client object by passing
 *                it the IP and port of the SafeCloud server to connect to
 * @param srvIP   The IP address as a string of the SafeCloud server to connect to
 * @param srvPort The port of the SafeCloud server to connect to
 */
void clientInit(char* srvIP,uint16_t& srvPort)
 {
  // Attempt to initialize the client object by passing the server connection parameters
  try
   { cli = new Client(srvIP,srvPort); }
  catch(sCodeException& excp)
   {
    // If the exception is relative to an invalid srvIP or srvPort passed via command-line arguments
    if(excp.scode == ERR_INVALID_SRV_ADDR || excp.scode == ERR_INVALID_SRV_PORT)
     {
      // "gently" notify the user of their expected syntax without recurring to traditional logging
      if(excp.scode == ERR_INVALID_SRV_ADDR)
       std::cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
      else
       if(excp.scode == ERR_INVALID_SRV_PORT)
        std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;

      // Delete the client object and silently exit
      delete(cli);
      exit(EXIT_FAILURE);
     }

    // Otherwise it is a (fatal) error associated with the client's X.509 certificates store creation, which
    // should be handled by the general handleScodeError() function, (which also terminates the execution)
    else
     handleScodeError(excp);
   }
 }


/* ========================= COMMAND-LINE INPUT PARAMETERS PARSING ========================= */

/**
 * @brief Prints a summary of the program's valid input options and values (parseCmdArgs() utility function)
 */
void printProgramUsageGuidelines()
 {
  std::cerr << "\nUsage:" << std::endl;
  std::cerr << "----- " << std::endl;
  std::cerr << "./client                   -> Connect to the SafeCloud server with default IP (" << SRV_DEFAULT_IP << ") and port (" << SRV_DEFAULT_PORT << ")" << std::endl;
  std::cerr << "./client [-a IP] [-p PORT] -> Connect to the SafeCloud server with a custom IPv4 address and/or a custom port PORT >= " << std::to_string(SRV_PORT_MIN) << std::endl;
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
  * @param srvIP   The resulting SafeCloud server IP address to connect to as a string
  * @param srvPort The resulting SafeCloud server port to connect to
  */
void parseCmdArgs(int argc, char** argv, char* srvIP, uint16_t& srvPort)
 {
  // Temporary options' values
  char     _srvIP[16] = SRV_DEFAULT_IP;   // The candidate value of the SafeCloud server IP address
  uint16_t _srvPort   = SRV_DEFAULT_PORT; // The candidate value of the SafeCloud server Port
  int      opt;                           // The current command-line option parsed by the getOpt() function

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

     // Missing IP or Port value
     case ':':
      if(optopt == 'a')   // Missing IP value
       std::cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
      else
       if(optopt == 'p')  // Missing Port value
        std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;
       else
        LOG_CRITICAL("Missing value for unknown parameter: \'" + std::to_string(optopt) + "\'")
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
  // NOTE: Rememeber that such values are NOT validated here
  strncpy(srvIP, _srvIP, 15);
  srvPort = _srvPort;
 }


/* ====================================== CLIENT MAIN ====================================== */

/**
 * @brief       The SafeCloud client entry point
 * @param argc  The number of command-line input arguments
 * @param argv  The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  /* ---------------------- Local Variables ---------------------- */
  char srvIP[16];      // The IP address as a string of the SafeCloud server to connect to
  uint16_t srvPort;    // The port of the SafeCloud server to connect to



//  // General Client Information
//  char name[CLI_NAME_MAX_LENGTH+1];  // The client's username in the SafeCloud application
//  char* downDir = nullptr;           // The client's download directory
//
//  // Client Cryptographic information
//  static X509_STORE* cliStore  = nullptr; // The client's X.509 certificates store
//  static EVP_PKEY*   cliRSAKey = nullptr; // The client's long-term RSA key pair


  /* ----------------------- Function Body ----------------------- */

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, OSSignalsCallback);
  signal(SIGTERM, OSSignalsCallback);
  signal(SIGQUIT, OSSignalsCallback);

  // Determine the IP and port of the SafeCloud server the client
  // application should connect to by parsing the command-line arguments
  parseCmdArgs(argc,argv,srvIP,srvPort);

  // Attempt to initialize the SafeCloud client object by passing
  // it the IP and port of the SafeCloud server to connect to
  clientInit(srvIP,srvPort);

  // Print the SafeCloud client welcome message

  // Call the client logic main loop
  clientLoop();

  // Exiting from the client's main loop implies that the application must terminate
  terminate(EXIT_SUCCESS);
 }