#ifndef SAFECLOUD_SAFECLOUDAPP_H
#define SAFECLOUD_SAFECLOUDAPP_H

/* SafeCloud Application Abstract Class Declaration */

/* ================================== INCLUDES ================================== */

// System Headers
#include <netinet/in.h>

// OpenSSL Headers
#include <openssl/evp.h>


class SafeCloudApp
 {
  protected:

   /* ================================= ATTRIBUTES ================================= */

   // The SafeCloud server listening socket type,
   // IP and Port in network representation order
   struct sockaddr_in _srvAddr;

   // The long-term RSA key pair of the actor executing
   // the SafeCloud application (client or server)
   EVP_PKEY* _rsaKey;

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
    * @return A boolean indicating whether the SafeCloudApp can be
    *         terminated directly or if it will autonomously terminate
    *         as soon as its pending operations will have completed
    */
   virtual bool shutdownSignalHandler() = 0;
 };


#endif //SAFECLOUD_SAFECLOUDAPP_H