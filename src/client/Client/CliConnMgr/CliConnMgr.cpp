/* SafeCloud Client Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "CliConnMgr.h"
#include "errlog.h"
#include <arpa/inet.h>

/* =============================== PRIVATE METHODS =============================== */

// TODO: Fix description depending on the _cliSessMgr.bufferFull() implementation
/**
 * @brief Waits and reads data from the connection socket
 *        until a full data block has been received
 * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
 * @throws ERR_SRV_DISCONNECTED Abrupt server disconnection
 */
void CliConnMgr::recvMsg()
 {
  try
   {
    // Wait until a full data block has been read from the connection socket
    while(!recvData())
     {
      /* TODO
         If the primary connection buffer is full (which may occur only in the session phase
         when sending/receiving large data), call the SessionMgr bufferFull() data to handle
         it (which at the end should clear the primary input buffer before proceeding)

      if(_priBufInd == _bufSize + 1)
       _cliSessMgr.bufferFull();
      */
     }
   }
  catch(sCodeException& recvExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_SRV_DISCONNECTED error
    // code and clear its additional information (representing the name of the client
    // associated with the connection manager, which on the client side is implicit)
    if(recvExcp.scode == ERR_PEER_DISCONNECTED)
     {
      recvExcp.scode = ERR_SRV_DISCONNECTED;
      recvExcp.addDscr = "";
     }

    // Rethrow the exception
    throw;
   }
 }


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief           CliConnMgr object constructor
 * @param csk       The connection socket associated with this manager
 * @param name      The client name associated with this connection
 * @param tmpDir    The connection's temporary directory
 * @param downDir   The client's download directory
 * @param rsaKey    The client's long-term RSA key pair
 * @param certStore The client's X.509 certificates store
 * @note The constructor also initializes the _cliSTSMMgr child object
 */
CliConnMgr::CliConnMgr(int csk, std::string* name, std::string* tmpDir, std::string* downDir, EVP_PKEY* rsaKey, X509_STORE* certStore)
                       : ConnMgr(csk,name,tmpDir), _downDir(downDir), _cliSTSMMgr(new CliSTSMMgr(rsaKey, *this, certStore)), _cliSessMgr(nullptr)
 {}


/**
 * @brief CliConnMgr object destructor, safely deleting the
 *        client-specific connection sensitive information
 */
CliConnMgr::~CliConnMgr()
 {
  // Delete the connection manager's child objects
  delete _cliSTSMMgr;
  delete _cliSessMgr;
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Executes the STSM client protocol, and
 *         initializes the communication's session phase
 * @throws All the STSM exceptions and most of the OpenSSL
 *         exceptions (see "scode.h" for more details)
 */
void CliConnMgr::startCliSTSM()
 {
  // Executes the STSM client protocol, exchanging STSM messages with
  // the SafeCloud server so to establish a shared AES_128 session key
  // and IV and to authenticate the client and server with one another
  _cliSTSMMgr->startCliSTSM();

  // Delete the CliSTSMMgr child object
  delete _cliSTSMMgr;
  _cliSTSMMgr = nullptr;

  // TODO
  // Instantiate the CliSessMgr child object
  //_cliSessMgr = new CliSessMgr();

  // Switch the connection to the SESSION phase
  _connState = SESSION;
 }
