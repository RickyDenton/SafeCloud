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
#include "errCodes/execErrCodes/execErrCodes.h"
#include "Client/Client.h"
#include "utils.h"
#include "DirInfo/DirInfo.h"
#include "ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include "errCodes/sessErrCodes/sessErrCodes.h"

/* ========================== GLOBAL STATIC VARIABLES ========================== */
Client* cli;  // The singleton Client object

/* ============================ FUNCTIONS DEFINITIONS ============================ */

/* ------------------------- Client Shutdown Management ------------------------- */

/**
 * @brief            SafeCloud Client shutdown handler, deleting the
 *                   Client object and terminating the application
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


/* ---------------------------- Client Initialization ---------------------------- */

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
  catch(execErrExcp& exeErrExcp)
   {
    // If the exception is relative to an invalid srvIP or srvPort passed via command-line arguments,
    // "gently" inform the user of their allowed values without recurring to the built-in logging macros
    if(exeErrExcp.exErrcode == ERR_SRV_ADDR_INVALID)
     std::cerr << "\nPlease specify a valid IPv4 address as value for the '-a' option (e.g. 192.168.0.1)" << "\n" << std::endl;
    else
     if(exeErrExcp.exErrcode == ERR_SRV_PORT_INVALID)
      std::cerr << "\nPlease specify a PORT >= " << std::to_string(SRV_PORT_MIN) << " for the '-p' option\n" << std::endl;

     // Otherwise the exception is relative to a fatal error associated with the client building its X.509 certificates store,
     // which should be handled by the general handleExecErrException() function, (which most likely will terminate the execution)
     else
      handleExecErrException(exeErrExcp);

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


  /* -------------------------------- TRIES -------------------------------- */


  /* -------------------------------- TRIES -------------------------------- */


  /* ============== AESGCMMGR Successful Encryption/Decryption ============== */

  try
   {
    /* -------------------------- Data Structures -------------------------- */

    // Buffers
    unsigned char _priBuf[100]; // Primary communication buffer
    unsigned char _secBuf[100]; // Secondary communication buffer

    // Cryptographic quantities
    unsigned char _skey[AES_128_KEY_SIZE]; // The connection's AES_GCM symmetric key
    IV*_iv;                                // The connection's AES_GCM initialization vector
    unsigned char _tag[16];                // The connection's AES_GCM Tag

    // Clear all buffers and the TAG
    memset(_priBuf,0,sizeof(_priBuf));
    memset(_secBuf,0,sizeof(_secBuf));
    memset(_tag,0,sizeof(_tag));

    /* --------------------------- IV Generation --------------------------- */

    // Seed the OpenSSL PRNG
    if(!RAND_poll())
     THROW_EXEC_EXCP(ERR_OSSL_RAND_POLL_FAILED, OSSL_ERR_DESC);

    // Randomly generate the IV's components
    if(RAND_bytes(_skey, AES_128_KEY_SIZE) != 1)
     THROW_EXEC_EXCP(ERR_OSSL_RAND_BYTES_FAILED, OSSL_ERR_DESC);

    _iv = new IV();

    /* ------------------------------- Setup ------------------------------- */

    std::cout << "SETUP" << std::endl;
    std::cout << "-----" << std::endl;

    // Instantiate the aesGcmMgr
    AESGCMMgr aesGcmMgr(&_skey[0], _iv);

    /**
     * Prepare the plaintext, logically divided in three parts:
     *
     *  1) AAD: "Hello "           (6 characters)
     *  2) PT1: "World"            (5 characters)
     *  3) PT2: " My Name is John" (16 characters)
     */
    strcpy(reinterpret_cast<char*>(_secBuf), "Hello World My Name is John");


    // Derive the expected plaintext and AAD sizes
    size_t ptSize = strlen(reinterpret_cast<const char*>(_secBuf));
    int aadSize = sizeof("Hello ") - 1; // Minus one because it automatically adds the '\0', which we don't want here

    // Log
    std::cout << "ptSize = " << ptSize << std::endl;
    std::cout << "aadSize = " << aadSize << std::endl;
    printf("\n");

    /* ---------------------------- Encryption ---------------------------- */

    std::cout << "ENCRYPTION" << std::endl;
    std::cout << "----------" << std::endl;

    int partCTSize;  // Partial CT size

    // Initialize the encryption
    aesGcmMgr.encryptInit();

    // Add the Authenticated Associated Data (AAD)
    aesGcmMgr.encryptAddAAD(&_secBuf[0], aadSize);

    // The AAD must be manually copied into the destination buffer/ciphertext
    memcpy(reinterpret_cast<char*>(_priBuf), "Hello ", aadSize);

    // Add the first plaintext block ("World", 5 characters)
    partCTSize = aesGcmMgr.encryptAddPT(&_secBuf[aadSize], 5, &_priBuf[aadSize]);
    std::cout << "partCTSize = " << partCTSize << std::endl;  // = 11 (aadSize + first ciphertext block size)

    // Add the second plaintext block (" My Name is John", 16 characters)
    partCTSize = aesGcmMgr.encryptAddPT(&_secBuf[partCTSize], 16, &_priBuf[partCTSize]);
    std::cout << "partCTSize = " << partCTSize << std::endl;  // = 27 (aadSize + first ciphertext block size + second ciphertext block size)

    // Finalize the encryption, get the TAG and the total ciphertext size (= last partCTSize)
    int ctSizeFinal = aesGcmMgr.encryptFinal(&_priBuf[partCTSize], _tag);
    std::cout << "ctSizeFinal = " << ctSizeFinal << std::endl;  // = 27

    printf("\n");

    /* ------------------------- Demo Adjustments ------------------------- */

    // TODO: The IV MUST NOT BE INCREMENTED IN THE DEMO (comment _iv->incIV() in AESGCMMgr::resetState()

    // Clear the secondary buffer
    memset(_secBuf,0,sizeof(_secBuf));

    // Suppose the AAD was received "as it is" in the primary buffer
    memcpy(reinterpret_cast<char*>(_secBuf), &_priBuf[0], aadSize);

    /* ---------------------------- Decryption ---------------------------- */

    std::cout << "DECRYPTION" << std::endl;
    std::cout << "----------" << std::endl;

    int partPTSize;  // Partial CT size

    // Initialize the decryption
    aesGcmMgr.decryptInit();

    // Add the Authenticated Associated Data (AAD)
    aesGcmMgr.decryptAddAAD(&_priBuf[0], aadSize);

    // Add the first ciphertext block ("World" encrypted, 5 characters)
    partPTSize = aesGcmMgr.decryptAddPT(&_priBuf[aadSize], 5, &_secBuf[aadSize]);
    std::cout << "partPTSize = " << partPTSize << std::endl; // = 11 (aadSize + first plaintext block size)

    // Add the second plaintext block (" My Name is John" encrypted, 16 characters)
    partPTSize = aesGcmMgr.decryptAddPT(&_priBuf[partPTSize], 16, &_secBuf[partPTSize]);
    std::cout << "partPTSize = " << partPTSize << std::endl;  // = 27 (aadSize + first plaintext block size + second plaintext block size)

    // Finalize the decryption, set the TAG and get the total plaintext size (= last partPTSize)
    int ptSizeFinal = aesGcmMgr.decryptFinal(&_priBuf[partPTSize], _tag);
    std::cout << "ptSizeFinal = " << ptSizeFinal << std::endl; // = 27

    printf("\n");

    /* --------------------------- Verification --------------------------- */

    std::cout << "VERIFICATION" << std::endl;
    std::cout << "------------" << std::endl;

    // Add a trailing NULL terminator to allow the
    // buffer contents to be interpreted as a string
    _secBuf[ptSizeFinal+1] = '\0';

    // Print the decrypted plaintext
    std::cout << "Decrypted Plaintext: " << _secBuf << std::endl;
   }
  catch(execErrExcp& execExcp)
   { handleExecErrException(execExcp); }
  catch(sessErrExcp& sessExcp)
   { handleSessErrException(sessExcp); }


  exit(EXIT_SUCCESS);

  /* -------------------------------- TRIES -------------------------------- */


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