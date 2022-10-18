#ifndef SAFECLOUD_SRVSESSMGR_H
#define SAFECLOUD_SRVSESSMGR_H

/* SafeCloud Server Session Manager Class Declaration */

/* ================================== INCLUDES ================================== */
#include "ConnMgr/SessMgr/SessMgr.h"


// Forward Declaration
class SrvConnMgr;

class SrvSessMgr : public SessMgr
 {
  private:

   // Server Session Manager Sub-states
   enum srvSessCmdState : uint8_t
    {
     SRV_IDLE,
     WAITING_CLI_CONF,
     WAITING_CLI_DATA,
     WAITING_CLI_COMPL
    };

   /* ================================= ATTRIBUTES ================================= */
   srvSessCmdState _srvSessMgrSubstate;  // The current server session manager sub-state
   SrvConnMgr&     _srvConnMgr;          // The associated SrvConnMgr parent object

   /* ============================== PRIVATE METHODS ============================== */

   /**
    * @brief Sends a session message signaling type to the client and performs the actions
    *        appropriate to session signaling types resetting or terminating the session
    * @param sessMsgSignalingType The session message signaling type to be sent to the client
    * @param errReason            An optional error reason to be embedded with the exception that
    *                             must be thrown after sending such session message signaling type
    * @throws ERR_SESS_INTERNAL_ERROR       The session manager experienced an internal error
    * @throws ERR_SESS_UNEXPECTED_MESSAGE   The session manager received a session message invalid for its current state
    * @throws ERR_SESS_MALFORMED_MESSAGE    The session manager received a malformed session message
    * @throws ERR_SESS_UNKNOWN_SESSMSG_TYPE The session manager received a session message of unknown type
    * @throws ERR_AESGCMMGR_INVALID_STATE   Invalid AES_128_GCM manager state
    * @throws ERR_OSSL_EVP_ENCRYPT_INIT     EVP_CIPHER encrypt initialization failed
    * @throws ERR_NON_POSITIVE_BUFFER_SIZE  The AAD block size is non-positive (probable overflow)
    * @throws ERR_OSSL_EVP_ENCRYPT_UPDATE   EVP_CIPHER encrypt update failed
    * @throws ERR_OSSL_EVP_ENCRYPT_FINAL    EVP_CIPHER encrypt final failed
    * @throws ERR_OSSL_GET_TAG_FAILED       Error in retrieving the resulting integrity tag
    * @throws ERR_CLI_DISCONNECTED          The client disconnected during the send()
    * @throws ERR_SEND_FAILED               send() fatal error
    */
   void sendSrvSessSignalMsg(SessMsgType sessMsgType);
   void sendSrvSessSignalMsg(SessMsgType sessMsgSignalingType, const std::string& errReason);


   // TODO
   void dispatchRecvSessMsg();

   /* ------------------------- 'UPLOAD' Callback Methods ------------------------- */

   void srvUploadStart();


  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief Server session manager object constructor, initializing the session parameters
    *        of the authenticated client associated with the srvConnMgr parent object
    * @param srvConnMgr A reference to the server connection manager parent object
    */
   explicit SrvSessMgr(SrvConnMgr& cliConnMgr);

   /* Same destructor of the SessMgr base class */

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Resets all session parameters in preparation for the next
    *        session command to be executed by the server session manager
    */
   void resetSrvSessState();

   /**
    * @brief  Server Session message handler, which:\name
    *            1) Unwraps a received session message wrapper from
    *               the primary into the secondary connection buffer\n
    *            2) Asserts the resulting session message to be allowed in
    *               the current server session manager state and substate\n
    *            3) Handles session-resetting or terminating signaling messages\n
    *            4) Handles session error signaling messages\n
    *            5) Valid session messages requiring further action are
    *               dispatched to the session callback method associated
    *               with the session manager current state and substate
    * @throws TODO (most session exceptions)
    */
   void srvSessMsgHandler();


   // TODO: Placeholder implementation
   void recvRaw(size_t recvBytes);
 };


#endif //SAFECLOUD_SRVSESSMGR_H
