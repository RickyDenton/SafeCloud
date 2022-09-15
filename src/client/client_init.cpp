/* SafeCloud Client entry point and initialization functions */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "defaults.h"
#include "errlog.h"

using namespace std;


/* ============================ FORWARD DECLARATIONS ============================ */
void clientLoop();        // Main client loop
bool askReconnection();   // Utility function asking the client whether to reconnect to the server


/* ============================== GLOBAL VARIABLES ============================== */

// The file descriptor of the client's connection socket with the server
int csk = -1;

// The SafeCloud server listening socket type, IP and Port in network representation order
static struct sockaddr_in srvAddr{};


/* ============================ FUNCTIONS DEFINITIONS ============================ */

/**
 * @brief            Closes the server connection and the client application
 * @param exitStatus The status to return to the caller via the exit() function
 */
void clientShutdown(int exitStatus)
 {
  // If the client connection socket is open, close it
  if(csk != -1)
   {
    // TODO: Add a "bye" message
    if(close(csk) != 0)
     LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))
    else
     LOG_DEBUG("Connection socket '" + to_string(csk) + "' closed")
   }

 // Print the closing message
 cout << "\nSafeCloud Client Terminated" << endl;

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
  clientShutdown(EXIT_SUCCESS);
 }


/**
 * @brief         Attempts to establish a connection with the SafeCloud server, prompting the user on whether
 *                to retry the connection in case of recoverable errors (ECONNREFUSED, ENETUNREACH, ETIMEDOUT)
 */
void serverConnect()
 {
  /* ---------------------- Local Variables ---------------------- */
  char srvIP[16]; // The server IP address (logging purposes)
  int connRes;    // Stores the server connection establishment result


  // Convert the server IP address from network to string representation for logging purposes
  inet_ntop(AF_INET, &srvAddr.sin_addr.s_addr, srvIP, INET_ADDRSTRLEN);

  /* ----------------------- Function Body ----------------------- */

  // Attempt to create a connection socket
  csk = socket(AF_INET, SOCK_STREAM, 0);
  if(csk == -1)
   {
    LOG_CODE_DSCR_FATAL(ERR_CSK_INIT_FAILED, strerror(errno))
    exit(EXIT_FAILURE);
   }

  LOG_DEBUG("Connection socket file descriptor: " + to_string(csk))

  cout << "Attempting to connect with SafeCloud server at " << srvIP << ":" << ntohs(srvAddr.sin_port) << "..." << endl;

  // Server connection attempt (which for recoverable errors can be repeated on user's discretion)
  do
   {
    connRes = connect(csk, (const struct sockaddr*)&srvAddr, sizeof(srvAddr));

    // If a connection could not be established
    if(connRes != 0)
     {
      // Log the connection error as for the ERRNO variable
      switch(errno)
       {
        /* These represent recoverable errors, which prompt the user whether to retry the connection */
        case ECONNREFUSED:
         LOG_WARNING("Connection refused from remote host (probably the SafeCloud server is not running)")
         break;

        case ENETUNREACH:
         LOG_ERROR("Network is unreachable")
         break;

        case ETIMEDOUT:
         LOG_ERROR("Server timeout in accepting the connection")
         break;

        /* Others are non-recoverable errors, with the client application that should be terminated */
        default:
         LOG_CODE_DSCR_FATAL(ERR_CSK_CONN_FAILED, strerror(errno))
         clientShutdown(EXIT_FAILURE);
       }

      // In case of recoverable errors, ask the user whether another connection
      // attempt should be performed, closing the client application if it should not
      if(!askReconnection())
       clientShutdown(EXIT_SUCCESS);

     } // if(!connRes)

   } while(connRes != 0);

  // At this point, connection with the server was established successfully
  cout << "Successfully connected with SafeCloud server at " << srvIP << ":" << to_string(ntohs(srvAddr.sin_port)) << endl;
 }


/**
 * @brief Prints a summary of the program's valid input options and values
 */
void printProgramUsageGuidelines()
 {
  cerr << "\nUsage:" << endl;
  cerr << "----- " << endl;
  cerr << "./client                   -> Connect to the SafeCloud server with default IP (" << SRV_DEFAULT_IP << ") and port (" << SRV_DEFAULT_PORT << ")" << endl;
  cerr << "./client [-a IP] [-p PORT] -> Connect to the SafeCloud server with a custom IPv4 address and/or a custom port PORT >= " << to_string(SRV_PORT_MIN) << endl;
  cerr << endl;
 }


/**
  * @brief         Parses the command-line input parameters and:\n
  *                1) If unknown options and/or values were passed, a summary of the expected calling syntax is printed and the application is stopped\n
  *                2) Valid input options and values override the default ones defined in sdef.h\n
  *                3) The resulting input options and values are validated and written in the reference and pointers provided by the caller
  * @param argc    The number of command-line input arguments
  * @param argv    The array of command line input arguments
  */
void parseCliArgs(int argc, char** argv)
 {
  char srvIP[16]   = SRV_DEFAULT_IP;   // The candidate value of the SafeCloud server IP address
  uint16_t srvPort = SRV_DEFAULT_PORT; // The candidate value of the SafeCloud server Port
  int  opt;                            // The current command-line option parsed by the getOpt() function

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
      strncpy(srvIP, optarg, 15);
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
       cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << endl;
      else
       if(optopt == 'p')  // Missing Port value
        cerr << "\nPlease specify a PORT >= " << to_string(SRV_PORT_MIN) << " for the '-p' option\n" << endl;
       else
        LOG_CRITICAL("Missing value for unknown parameter: \'" + to_string(optopt) + "\'")
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

 // "srvIP" must consist of a valid IPv4 address, which can be ascertained
 // by converting its value from string to its network representation as:
 if(inet_pton(AF_INET, srvIP, &srvAddr.sin_addr.s_addr) <= 0)
  {
   cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << endl;
   exit(EXIT_FAILURE);
  }

 // If srvPort >= SRV_PORT_MIN, convert it to the network byte order within the "srvAddr" structure
 if(srvPort >= SRV_PORT_MIN)
  srvAddr.sin_port = htons(srvPort);
 else    // Otherwise, report the error
  {
   cerr << "\nPlease specify a PORT >= " << to_string(SRV_PORT_MIN) << " for the '-p' option\n" << endl;
   exit(EXIT_FAILURE);
  }

  LOG_DEBUG("Safecloud Server parameters: IP = " + string(srvIP) + ", Port = " + to_string(srvPort))
 }


/**
 * @brief The SafeCloud client entry point
 * @param argc    The number of command-line input arguments
 * @param argv    The array of command line input arguments
 */
int main(int argc, char** argv)
 {
  /* ---------------------- Local Variables ---------------------- */


  /* ----------------------- Function Body ----------------------- */

  // Register the SIGINT, SIGTERM and SIGQUIT signals handler
  signal(SIGINT, osSignalsCallbackHandler);
  signal(SIGTERM, osSignalsCallbackHandler);
  signal(SIGQUIT, osSignalsCallbackHandler);

  // Set the server socket type to IPv4
  srvAddr.sin_family = AF_INET;

  // Determine the IP and port of the SafeCloud server the client
  // application should connect to by parsing the command-line arguments
  parseCliArgs(argc, argv);

  // TODO: Client Welcome Message

  // TODO: Client Login (username + password)

  // TODO: Parse Client Files

  // Attempt to establish a connection with the SafeCloud
  // server, obtaining the associated connection socket
  serverConnect();

  // TODO: Client Key Exchange Protocol

  // TODO: Placeholder implementation
  clientLoop();

  clientShutdown(EXIT_SUCCESS);
 }