#ifndef SAFECLOUD_GUEST_H
#define SAFECLOUD_GUEST_H

/* SafeCloud guest object definition */

/* ================================== INCLUDES ================================== */
#include "client.h"
#include "crypto/STSM.h"

/* ============================== TYPE DEFINITIONS ============================== */

/**
 * @brief The guest class implementation
 */
class guest : public client
 {
  private:

   /* ------------------------- Attributes ------------------------- */

   // TODO: Placeholders
   srvXchangeStage keyXchangeStage;
   int _srv_eph_pubk;
   int _srv_eph_privk;
   int _guest_eph_pubk;
   int _session_key;

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   guest(int csk,const char* ip, int port);  // Same of the client interface

   ~guest();

   /* ----------------------- Other Methods ----------------------- */

   // Read incoming client data
   postAction readData();
 };

#endif //SAFECLOUD_GUEST_H
