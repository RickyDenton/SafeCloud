/* Entry point and client connection manager of the SafeCloud client application */

/* ================================== INCLUDES ================================== */

// Miscellaneous Libraries
#include <iostream>
#include <signal.h>
#include <unistd.h>
#include <string.h>

// TCP/IP Libraries
#include <arpa/inet.h>

// SafeCloud Libraries
#include "safecloud/sdef.h"
#include "safecloud/scode.h"
#include "safecloud/sutils.h"

using namespace std;

/* ============================== GLOBAL VARIABLES ============================== */

// The file descriptor of the client's connection socket with the server
int csk = -1;

// The SafeCloud server listening socket type, IP and Port in network representation order
// TODO: Check if this is required as a global variable and not simply as a parameter passed by the main()
//       to the parseCliArgs() and finally to the serverConnect() function (to support reconnection attempts?)
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
void osSignalsCallbackHandler(int signum)
 {
  LOG_INFO("Shutdown signal received, closing the application...")
  clientShutdown(EXIT_SUCCESS);
 }


/**
 * @brief Prompt the user on whether to attempt to re-establish a connection with the SafeCloud Server
 * @return 'true' if the user wants to reconnect, 'false' otherwise
 */
bool askReconnection()
 {
  int retryConn;  // A character representing the user choice on whether attempting to re-establish connection with the server (y/Y or n/N)

  cout << "Try again to connect with the server? (Y/N): ";

  // Read the first y/Y or n/N character from standard input
  retryConn = getYNChar();

  // Return true or false depending on the user's choice
  if((retryConn == 'Y') || (retryConn == 'y'))
   return true;
  return false;
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
  LOG_DEBUG("Connected with server @ "+ string(srvIP) + ":" + to_string(ntohs(srvAddr.sin_port)))
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


// TODO: Placeholder implementation
bool connRecovery()
 {
  int retryConn;

  // Ask the user on whether a reconnection
  // attempt with the server should be performed,
  if(askReconnection())
   {
    // If it should, close the current connection socket
    if(close(csk) != 0)
     LOG_CODE_DSCR_CRITICAL(ERR_CSK_CLOSE_FAILED, strerror(errno))
    else
     {
      LOG_DEBUG("Connection socket '" + to_string(csk) + "' closed")
      csk = -1;
     }

    // Attempt to reconnect with the server
    serverConnect();

    // If the connection was successful, inform the client loop that the execution can continue
    // TODO: CHECK
    return true;
   }

  // Otherwise, inform the client loop that execution should end
  else
   return false;
 }




bool recvCheck(char* buf,size_t bufSize,ssize_t& recvSize)
 {
 // Attempt to read data from the client's connection socket
 recvSize = recv(csk, buf, bufSize - 1, 0);

 LOG_DEBUG("recv() returned " + recvSize)

 // Depending on the recv() return:
 switch(recvSize)
  {
   // Generic Error
   case -1:

    // Log the error
    LOG_CODE_DSCR_ERROR(ERR_CSK_RECV_FAILED, strerror(errno))

    // Inform that the recv() contents are not valid and
    // that the current server connection should be aborted
    return false;


    // The server orderly closed the connection
    case 0:

     // TODO: check, possibly merge with the previous case
     // Log that the server has orderly disconnected
     LOG_WARNING("The server has orderly disconnected")

     // Inform that the recv() contents are not valid and
     // that the current server connection should be aborted
     return false;

     // recvSize > 0, valid data was read
    default:

     // Add the string termination character at the end of the data for safety purposes
     buf[recvSize] = '\0';

     // Inform that the recv() contents are valid
     return true;
  }
 }


// TODO: Placeholder implementation
void clientBody()
 {
  char cliMsg[1024];
  char srvAnswer[1024];
  ssize_t recvSize;

  while(1)
   {
    cout << "Message to send to server: ";
    cin >> cliMsg;

    send(csk, cliMsg, strlen(cliMsg), 0);

    // If the client wants to close the communication, exit from the clientBody loop
    if(!strcmp(cliMsg, "close"))
     break;

    // Otherwise read data from socket, ensuring that no error occured
    if(recvCheck(srvAnswer,sizeof(srvAnswer),recvSize))
     {
      // If no error, just echo the server message
      cout << "Server answered: \"" << srvAnswer << "\"" << endl;
     }

    // Otherwise the current server connection must be closed and, as an error recovery
    // mechanism, ask the client on whether a new connection attempt should be performed
    else
     if(!connRecovery())
      break;
   }
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
  clientBody();

  clientShutdown(EXIT_SUCCESS);
 }