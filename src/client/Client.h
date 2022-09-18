#ifndef SAFECLOUD_CLIENT_H
#define SAFECLOUD_CLIENT_H

/* SafeCloud Application Client */

#include <openssl/evp.h>

class Client
 {
  private:

   /* ========================= Attributes ========================= */
   char* _name;             // Username (unique in the SafeCloud application)

   // Client Directories Paths
   char* _downDir;          // Download directory
   char* _tempDir;          // Temporary files directory

   // Client Cryptographic Data
   EVP_PKEY*   _rsaKey;     // Long-term RSA key pair
   X509_STORE* _certStore;  // Certificates Store

   // Server Connection parameters
   char*      _srvIP;       // SafeCloud server's IP address
   const int* _srvPort;     // SafeCloud server's Port

   // Client Connection Manager
   CliConnMgr* _cliConnMgr;

   /* =========================== Methods =========================== */
   // TODO
   // bool srvConnect();
   // bool uploadFile();
   // bool downloadFile();
   // bool deleteFile();
   // bool renameFile();
   // bool listFiles();

  public:

   /* ================= Constructors and Destructor ================= */
   Client(char* name, char* downDir, char* tempDir, EVP_PKEY* rsaKey, X509_STORE* certStore, char* srvIP, const int& srvPort);
   ~Client();

   /* ======================== Other Methods ======================== */

   // TODO
   // void clientBody();
 };


#endif //SAFECLOUD_CLIENT_H
