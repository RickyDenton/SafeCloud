#ifndef SAFECLOUD_USER_H
#define SAFECLOUD_USER_H

/* SafeCloud user object definition */

/* ================================== INCLUDES ================================== */
#include "client.h"

/* ============================== TYPE DEFINITIONS ============================== */

/**
 * @brief The guest class implementation
 */
class user : public client
 {
  private:

   /* ------------------------- Attributes ------------------------- */

   // TODO: Placeholders
   int _session_key;
   char _name[31];
   int _plaintext;
   int _ciphertext;

  public:

   /* ---------------- Constructors and Destructor ---------------- */
   user(int csk,const char* ip, int port, char* name, int session_key);

   ~user();

   /* ----------------------- Other Methods ----------------------- */

   // Read incoming client data
   postAction readData();
 };

#endif //SAFECLOUD_USER_H