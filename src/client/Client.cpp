/* SafeCloud Application Client Implementation*/

/* ================================== INCLUDES ================================== */
#include "Client.h"
#include "utils.h"
#include <openssl/x509_vfy.h>

/* =============================== PRIVATE METHODS =============================== */
// bool srvConnect();
// bool uploadFile();
// bool downloadFile();
// bool deleteFile();
// bool renameFile();
// bool listFiles();


/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief            Client object constructor
 * @param name       Username (unique in the application)
 * @param downDir    Download directory
 * @param tempDir    Temporary files directory
 * @param rsaKey     Long-term RSA key pair
 * @param _certStore Certificates Store
 * @param srvIP      SafeCloud server's IP address
 * @param _srvPort   SafeCloud server's Port
 */
Client::Client(char* name, char* downDir, char* tempDir, EVP_PKEY* rsaKey, X509_STORE* certStore, char* srvIP, const int& srvPort)
              : _name(), _downDir(downDir), _tempDir(tempDir), _rsaKey(rsaKey), _certStore(certStore), _srvIP(), _srvPort(&srvPort), _cliConnMgr(nullptr)
 {}


/**
 * @brief Client object destructor, which safely deletes its sensitive attributes
 */
Client::~Client()
 {
  // Delete all child objects
  delete _cliConnMgr;

  // Safely erase all sensitive attribute
  safeMemset0(reinterpret_cast<void*&>(_name), 31);
  EVP_PKEY_free(_rsaKey);
  X509_STORE_free(_certStore);
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

// void clientLoop();