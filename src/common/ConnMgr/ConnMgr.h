#ifndef SAFECLOUD_CONNMGR_H
#define SAFECLOUD_CONNMGR_H

#include "defaults.h"
#include "ConnMgr/IVMgr/IVMgr.h"
#include <string>

/* SafeCloud Connection Manager */

class ConnMgr
 {
  protected:

   // Connection current state
   enum connState
    {
     KEYXCHANGE,  // Connection in the STSM key establishment phase
     SESSION      // Connection in the session phase
    };

   /* ================================= ATTRIBUTES ================================= */

   // General connection information
   connState    _connState;           // Connection current state (key establishment or session)
   const int    _csk;                 // The connection socket associated with this manager
   std::string* _name;                // The client's name associated with this connection
   std::string* _tmpDir;              // The connection's temporary directory

   // Communication Buffers
   unsigned char      _priBuf[CONN_BUF_SIZE];  // Primary communication buffer
   unsigned int       _priBufInd;              // Index of the first available byte, or number of
                                               // significant bytes, in the primary communication buffer
   unsigned char      _secBuf[CONN_BUF_SIZE];  // Secondary communication buffer
   unsigned int       _secBufInd;              // Index of the first available byte, or number of
                                               // significant bytes, in the secondary communication buffer
   const unsigned int _bufSize;                // Communication buffers size (CONN_BUF_SIZE)
   uint16_t           _recvBlockSize;          // Expected size of a data block being received

   // Cryptographic quantities
   unsigned char _skey[SKEY_SIZE];  // The connection's AES_GCM symmetric key
   IVMgr* _iv;                      // The connection's AES_GCM initialization vector

   /* ============================== PROTECTED METHODS ============================== */

   /**
    * @brief Deletes the contents of the connection's temporary directory
    */
   void cleanTmpDir();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief        ConnMgr object constructor
    * @param csk    The connection socket associated with this manager
    * @param name   The client name associated with this connection
    * @param tmpDir The connection's temporary directory
    */
   ConnMgr(int csk, std::string* name, std::string* tmpDir);

   /**
    * @brief Connection Manager object destructor, which:\n
    *          1) Closes its associated connection socket\n
    *          2) Delete the contents of the connection's temporary directory\n
    *          3) Safely deletes all the connection's sensitive information
    */
   ~ConnMgr();

   /* ============================= OTHER PUBLIC METHODS ============================= */

  /* ---------------------------------- Data I/O ---------------------------------- */

  /**
    * @brief Marks the contents of the primary connection buffer as
    *        consumed, resetting the index of its first significant byte
    */
  void clearPriBuf();

  /**
   * @brief Marks the contents of the secondary connection buffer as
   *        consumed, resetting the index of its first significant byte
   */
  void clearSecBuf();

  /**
   * @brief  Reads bytes belonging to a same data block from the connection socket into the primary connection buffer,
   *         updating the number of significant bytes in it and possibly the expected size of the data block to be received
   * @return A boolean indicating whether a full data block is available for consumption in the primary connection buffer
   * @throws ERR_CSK_RECV_FAILED   Error in receiving data from the connection socket
   * @throws ERR_PEER_DISCONNECTED Abrupt peer disconnection
   */
  bool recvData();


  void sendData();


  // TODO
   // sendOk()
   // sendClose()
   // sendCloseError()
 };


#endif //SAFECLOUD_CONNMGR_H
