/* SafeCloud Client Connection Manager Implementation */

/* ================================== INCLUDES ================================== */
#include "errCodes/execErrCodes/execErrCodes.h"
#include "CliConnMgr.h"


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief           CliConnMgr object constructor
 * @param csk       The connection socket associated with this manager
 * @param name      The client name associated with this connection
 * @param tmpDir    The connection's temporary directory
 * @param downDir   The client's download directory absolute path
 * @param rsaKey    The client's long-term RSA key pair
 * @param certStore The client's X.509 certificates store
 * @note The constructor also initializes the _cliSTSMMgr child object
 */
CliConnMgr::CliConnMgr(int csk, std::string* name, std::string* tmpDir,
                       std::string* downDir, EVP_PKEY* rsaKey, X509_STORE* certStore)
 : ConnMgr(csk,name,tmpDir), _downDir(downDir),
   _cliSTSMMgr(new CliSTSMMgr(rsaKey, *this, certStore)), _cliSessMgr(nullptr)
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
  _connPhase = SESSION;
 }


/**
 * @brief  Returns a pointer to the session manager's child object
 * @return A pointer to the session manager's child object
 * @throws ERR_CONNMGR_INVALID_STATE The connection is not in the session phase
 */
CliSessMgr* CliConnMgr::getSession()
 {
  if(_connPhase != SESSION || _cliSessMgr == nullptr)
   THROW_EXEC_EXCP(ERR_CONNMGR_INVALID_STATE,
                   "Attempting to retrieve the child session object with "
                   "the connection still in the STSM key exchange phase");
  return _cliSessMgr;
 }