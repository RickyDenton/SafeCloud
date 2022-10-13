/* SafeCloud Client Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "CliConnMgr.h"
#include "errCodes/execErrCodes/execErrCodes.h"

/* =============================== PRIVATE METHODS =============================== */

// TODO: Fix description depending on the _cliSessMgr.bufferFull() implementation
/**
 * @brief Waits and reads data from the connection socket
 *        until a full data block has been received
 * @throws ERR_CSK_RECV_FAILED  Error in receiving data from the connection socket
 * @throws ERR_SRV_DISCONNECTED Abrupt server disconnection
 */
void CliConnMgr::cliRecvMsg()
 {
  try
   { recvMsg(); }
  catch(execErrExcp& recvExcp)
   {
    // Change a ERR_PEER_DISCONNECTED into the more specific ERR_SRV_DISCONNECTED error
    // code and clear its additional information (representing the name of the client
    // associated with the connection manager, which on the client side is implicit)
    if(recvExcp.exErrcode == ERR_PEER_DISCONNECTED)
     {
      recvExcp.exErrcode = ERR_SRV_DISCONNECTED;
      recvExcp.addDscr = nullptr;
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
 *         exceptions (see "execErrCode.h" for more details)
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

  // Instantiate the CliSessMgr child object
  _cliSessMgr = new CliSessMgr(*this);

  // Switch the connection to the SESSION phase
  _connState = SESSION;
 }


/**
 * @brief  Returns a pointer to the session manager's child object
 * @return A pointer to the session manager's child object
 * @throws ERR_CONN_NO_SESSION The connection is not in the session phase
 */
CliSessMgr* CliConnMgr::getSession()
 {
  if(_connState != SESSION || _cliSessMgr == nullptr)
   THROW_EXEC_EXCP(ERR_CONN_NO_SESSION);
  return _cliSessMgr;
 }