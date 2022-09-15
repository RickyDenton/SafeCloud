#ifndef SAFECLOUD_STSM_H
#define SAFECLOUD_STSM_H

/* Definitions of the Station-To-Station-Modified (STSM) key exchange protocol used by the SafeCloud application */

/* ============================== TYPE DEFINITIONS ============================== */

// Client Key Exchange Stage
enum cliXchangeStage
 {
  WAITING_SRV_EPUBK,
  WAITING_SRV_OK
 };

// Server Key Exchange Stage
enum srvXchangeStage
{
 WAITING_CLI_EPUBK,
 WAITING_CLI_AUTH
};

#endif //SAFECLOUD_STSM_H
