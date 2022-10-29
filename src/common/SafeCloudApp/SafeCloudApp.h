#ifndef SAFECLOUD_SAFECLOUDAPP_H
#define SAFECLOUD_SAFECLOUDAPP_H

/* SafeCloud Abstract Application Class Declaration */

/* ================================== INCLUDES ================================== */
#include <openssl/evp.h>
#include <netinet/in.h>

class SafeCloudApp
 {
  protected:

   /* ================================= ATTRIBUTES ================================= */

   // The SafeCloud server listening socket type,
   // IP and Port in network representation order
   struct sockaddr_in _srvAddr;

   // The long-term RSA key pair of the actor executing
   // the SafeCloud application (client or server)
   EVP_PKEY*          _rsaKey;

   /* ------------------------- SafeCloudApp Object Flags ------------------------- */

   // Whether the SafeCloud application has
   // established a connection with the remote peer
   bool _connected;

   // Whether the SafeCloud application is performing shutdown operations
   bool _shutdown;

  public:

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief SafeCloudApp base constructor
    */
   SafeCloudApp();

   /**
    * @brief SafeCloudApp virtual destructor, making the class abstract
    */
   virtual ~SafeCloudApp() = 0;

   /* ============================= OTHER PUBLIC METHODS ============================= */

   /**
    * @brief Starts the SafeCloud application with the
    *        parameters provided in its constructor
    */
   virtual void start() = 0;

   /**
    * @brief  SafeCloudApp shutdown signal handler, to be called upon
    *         receiving an OS signal aimed at shutting down the application
    * @return A boolean indicating whether the SafeCloudApp is not connected
    *         or idle and so can be deleted directly or whether the application
    *         is busy and so will autonomously shutdown as soon as possible
    */
   virtual bool shutdownSignalHandler() = 0;
 };


#endif //SAFECLOUD_SAFECLOUDAPP_H
