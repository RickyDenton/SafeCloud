/* SafeCloud Client main driver */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// OpenSSL Libraries
#include <openssl/evp.h>
#include <cstring>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"
#include "Client/Client.h"
#include "utils.h"
#include "client_utils.h"

/* ========================== GLOBAL STATIC VARIABLES ========================== */
static Client* cli;  // The singleton Client object

/* ============================ FUNCTIONS DEFINITIONS ============================ */

/* ------------------------- Client Shutdown Management ------------------------- */

/**
 * @brief            Deletes the Client object and terminates the SafeCloud Client application
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
 *                 - If the client object is connected with the SafeCloud server, it
 *                   is instructed gracefully close such connection and terminate
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

  // Otherwise instruct the client object to gracefully close the server connection and terminate
  else
   {
    LOG_INFO("Shutdown signal received, closing the server's connection...")
    cli->shutdownSignal();
   }
}

/* ------------------------------ Client Main Loop ------------------------------ */

// TODO!
bool recvCheck(int csk, char* buf,size_t bufSize,ssize_t& recvSize)
 {
 // Attempt to read data from the client's connection socket
 recvSize = recv(csk, buf, bufSize - 1, 0);

 LOG_DEBUG("recv() returned " + std::to_string(recvSize))

 // Depending on the recv() return:
 switch(recvSize)
  {
  // Generic Error
  case -1:

   // Log the error
   LOG_SCODE(ERR_CSK_RECV_FAILED,ERRNO_DESC);

   // Inform that the recv() contents are not valid and
   // that the current server connection should be aborted
   return false;


   // The server orderly closed the connection
  case 0:

   // TODO: check, possibly merge with the previous case
   // Log that the server has orderly disconnected
   LOG_WARNING("The server has abruptly disconnected")

   // Inform that the recv() contents are not valid and
   // that the current server connection should be aborted
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



// TODO!
/**
 * @brief Depending on the user's choice, attempts to reconnect with the SafeCloud server
 * @return 'true' if connection with the SafeCloud server was successfully re-established, or 'false' otherwise
 */
int srvConnDown(int& csk)
 {
  // Ask the user on whether a reconnection attempt with the server should be performed,
  if(askReconnection())
   {
    // If it should, close the current connection socket
    if(close(csk) != 0)
     LOG_SCODE(ERR_CSK_CLOSE_FAILED, strerror(errno));
    else
     {
      LOG_DEBUG("Connection socket '" + std::to_string(csk) + "' closed")
      csk = -1;
     }

    // Attempt to reconnect with the server
    return cli->srvConnect();
  }


  // Otherwise, inform the client loop that connection was not
  // re-established (and so that the application must terminate)
  return false;
 }

int clientLoop()
 {
  bool login;
  int csk;

  login = cli->login();
  if(login)
   {
    std::cout << "LOGGED IN" << std::endl;

    csk = cli->srvConnect();
    if(csk != -1)
     {
      std::cout << "CONNECTED" << std::endl;

      char cliMsg[1024];
      char srvAnswer[1024];
      ssize_t recvSize;        // Number of bytes read from the connection socket

      while(1)
       {
        std::cout << "Message to send to server: ";
        std::cin >> cliMsg;

        send(csk, cliMsg, strlen(cliMsg), 0);

        // If the client wants to close the communication, exit from the clientLoop loop
        if(!strcmp(cliMsg, "close"))
         break;

        // Otherwise attempt to read data from the client's connection socket, checking for errors
        if(recvCheck(csk, srvAnswer, sizeof(srvAnswer), recvSize))
         {
          // If no error, just echo the server message
          std::cout << "Server answered: \"" << srvAnswer << "\"" << std::endl;
         }

         // Otherwise the current server connection must be closed and, as an error recovery
         // mechanism, ask the client on whether a new connection attempt should be performed
        else
         if((csk = srvConnDown(csk)) != -1)
          break;
       }
     }
    else
     std::cout << "NOT CONNECTED" << std::endl;
   }
  else
   std::cout << "NOT LOGGED IN" << std::endl;

  return(EXIT_SUCCESS);
 }

/* ---------------------------- Client Initialization ---------------------------- */

/**
 * @brief Prints the SafeCloud client welcome message
 */
void printWelcomeMessage()
 {
  std::cout << "   _____        __      _____ _                 _ \n";
  std::cout << "  / ____|      / _|    / ____| |               | |\n";
  std::cout << " | (___   __ _| |_ ___| |    | | ___  _   _  __| |\n";
  std::cout << "  \\___ \\ / _` |  _/ _ \\ |    | |/ _ \\| | | |/ _` |\n";
  std::cout << "  ____) | (_| | ||  __/ |____| | (_) | |_| | (_| |\n";
  std::cout << " |_____/ \\__,_|_| \\___|\\_____|_|\\___/ \\__,_|\\__,_|" << std::endl;
 }


/**
 * @brief         Attempts to initialize the SafeCloud Client object by passing
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
    // If the exception is relative to an invalid srvIP or srvPort passed via command-line arguments,
    // "gently" inform the user of their allowed values without recurring to the built-in logging macros
    if(excp.scode == ERR_SRV_ADDR_INVALID)
     std::cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
    else
     if(excp.scode == ERR_SRV_PORT_INVALID)
      std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;

     // Otherwise the exception is relative to a fatal error associated with the client building its X.509 certificates store,
     // which should be handled by the general handleScodeException() function, (which most likely will terminate the execution)
     else
      handleScodeException(excp);

    // If no fatal error occurred, delete the Client object and exit silently
    delete(cli);
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
      //       which later accounted in asserting that it must be srvPort >= SRV_PORT_MIN > 0
      //
#pragma clang diagnostic push
#pragma ide diagnostic ignored "cert-err34-c"
      _srvPort = atoi(optarg);
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
  // NOTE: Remember that such values are NOT validated here
  strncpy(srvIP, _srvIP, 15);
  srvPort = _srvPort;
 }

/* -------------------------------- Client Main -------------------------------- */

/**
 * @brief       The SafeCloud client entry point
 * @param argc  The number of command-line input arguments
 * @param argv  The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  char srvIP[16];      // The IP address as a string of the SafeCloud server to connect to
  uint16_t srvPort;    // The port of the SafeCloud server to connect to

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

  // Print the SafeCloud client welcome message
  printWelcomeMessage();

  // Call the client logic main loop
  clientLoop();

  // Exiting from the client's main loop implies that the application must terminate
  terminate(EXIT_SUCCESS);
 }