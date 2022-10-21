#ifndef SAFECLOUD_CONNMGR_H
#define SAFECLOUD_CONNMGR_H

/* SafeCloud Connection Manager Declarations */

/* ================================== INCLUDES ================================== */
#include "defaults.h"
#include "ConnMgr/IV/IV.h"
#include "ossl_crypto/AES_128_CBC.h"
#include "ConnMgr/SessMgr/AESGCMMgr/AESGCMMgr.h"
#include <string>

class ConnMgr
 {
  protected:

   // Connection Phases
   enum connPhase
    {
     KEYXCHANGE,  // STSM key establishment phase
     SESSION      // Session phase
    };

   // Connection manager reception modes
   enum recvMode : uint8_t
    {
     // Receive either a STSMMsg or a SessMsgWrapper, with
     // its first 16 bits representing the total message size
     RECV_MSG,

     // Receive raw data
     RECV_RAW
    };

   /* ================================= ATTRIBUTES ================================= */

   /* ----------------------- Connection General Information ----------------------- */
   connPhase    _connPhase;  // The connection's current phase (STSM key establishment or session)
   recvMode     _recvMode;   // The connection manager's current reception mode (RECV_MSG or RECV_RAW)
   const int    _csk;        // The connection socket associated with this manager

   /* ------------------------ Primary Communication Buffer ------------------------ */

   /*
    * This buffer is used for sending and receiving data to and
    * from the peer associated with the connection socket "_csk"
    */

   // Primary communication buffer
   unsigned char      _priBuf[CONN_BUF_SIZE + AES_128_GCM_TAG_SIZE];

   // Primary communication buffer size
   const unsigned int _priBufSize;

   // Index of the first available byte (or number of
   // significant bytes) in the primary communication buffer
   unsigned int       _priBufInd;

   // Expected size of the data block (message or raw) to be received
   uint32_t           _recvBlockSize;

   /* ----------------------- Secondary Communication Buffer ----------------------- */

   /*
    * This buffer is used as a support for preparing the data to be sent to or parsing
    * the data received from the communication peer (e.g. encryption and decryption)
    */

   // Secondary communication buffer
   unsigned char      _secBuf[CONN_BUF_SIZE];

   // Secondary communication buffer size
   const unsigned int _secBufSize;

   /* -------------------- Connection Cryptographic Quantities -------------------- */
   unsigned char _skey[AES_128_KEY_SIZE];   // The connection's symmetric key
   IV* _iv;                                 // The connection's initialization vector

   /* ----------------------- Connection Client Information ----------------------- */
   std::string* _name;   // The name of the client associated with this connection
   std::string* _tmpDir; // The absolute path of the temporary directory of the client associated with this connection


   /* =============================== FRIEND CLASSES =============================== */
   friend class SessMgr;
   friend class CliSessMgr;
   friend class SrvSessMgr;

   /* ============================== PROTECTED METHODS ============================== */

   /**
    * @brief Deletes the contents of the connection's temporary directory
    *        (called within the connection manager's destructor)
    */
   void cleanTmpDir();

   /* ---------------------------------- Data I/O ---------------------------------- */

   /**
    * @brief Marks the contents of the primary connection buffer as consumed,
    *        resetting the index of its first significant byte and the
    *        expected size of the data block (message or raw) to be received
    */
   void clearPriBuf();

   /**
    * @brief Sends bytes from the start of the primary connection buffer to the connection peer
    * @param numBytes The number of bytes to be sent (must be <= _priBufSize)
    * @throws ERR_SEND_OVERFLOW     Attempting to send a number of bytes > _priBufSize
    * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED       send() fatal error
    */
  void sendData(unsigned int numBytes);

   /**
    * @brief Sends a message stored in the primary communication buffer, with
    *        its first 16 bits representing its size, to the connection peer
    * @throws ERR_PEER_DISCONNECTED The connection peer disconnected during the send()
    * @throws ERR_SEND_FAILED       send() fatal error
    */
   void sendMsg();

   /**
    * @brief Blocks until a full message has been read from the
    *        connection socket into the primary communication buffer
    * @throws ERR_CONNMGR_INVALID_STATE Attempting to receive a message while the
    *                                   connection manager is in the RECV_RAW mode
    * @throws ERR_CSK_RECV_FAILED       Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED     The connection peer has abruptly disconnected
    */
   void recvMsg();

   /**
    * @brief  Reads bytes belonging to a same data block from the connection socket into the primary connection buffer,
    *         updating its number of significant bytes and, with the manager in RECV_MSG mode, the expected size of the
    *         message to be received, if such quantity is not already set
    * @return - ConnMgr in RECV_MSG mode: A boolean indicating whether a complete message\n
    *                                     has been received in the primary connection buffer\n
    *         - ConnMgr in RECV_RAW mode: The number of bytes read in the primary connection buffer
    * @throws ERR_CSK_RECV_FAILED   Error in receiving data from the connection socket
    * @throws ERR_PEER_DISCONNECTED The connection peer has abruptly disconnected
    */
   size_t recvData();

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief        ConnMgr object constructor
    * @param csk    The connection socket associated with this manager
    * @param name   The name of the client associated with this connection
    * @param tmpDir The absolute path of the temporary directory associated with this connection
    */
   ConnMgr(int csk, std::string* name, std::string* tmpDir);

   /**
    * @brief Connection Manager object destructor, which:\n
    *          1) Closes its associated connection socket\n
    *          2) Delete the contents of the connection's temporary directory\n
    *          3) Safely deletes all the connection's sensitive information
    */
   ~ConnMgr();
 };


#endif //SAFECLOUD_CONNMGR_H
