/* Station-to-Station-Modified (STSM) Key Exchange Protocol Client Manager Implementation */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include "CliSTSMMgr.h"
#include "../CliConnMgr.h"
#include "scode.h"
#include "errlog.h"
#include "ConnMgr/STSMMgr/STSMMsg.h"

/* =============================== PRIVATE METHODS =============================== */

// TODO
void CliSTSMMgr::checkCliSTSMError()
 {
  try
   { checkSTSMError(((STSMMsg&&)(_cliConnMgr._priBuf)).header.type); }
  catch(sCodeException& excp)
   {
    // Substitute with more specific
    switch(excp.scode)
     {
      case ERR_STSM_MALFORMED_MSG:
       excp.scode = ERR_STSM_CLI_MALFORMED_MSG;
      break;

      case ERR_STSM_CHALLENGE_FAILED:
       excp.scode = ERR_STSM_CLI_CHALLENGE_FAILED;
      break;

      case ERR_STSM_CERT_REJECTED:
       excp.scode = ERR_STSM_CLI_CERT_REJECTED;
      break;

      case ERR_STSM_LOGIN_FAILED:
       excp.scode = ERR_STSM_CLI_LOGIN_FAILED;
      break;

      case ERR_STSM_UNKNOWN_TYPE:
       excp.scode = ERR_STSM_CLI_UNKNOWN_TYPE;
      break;

      default:
       break;
     }
    throw;
   }
 }

/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief                  CliSTSMMgr object constructor
 * @param myRSALongPrivKey The client's long-term RSA key pair
 * @param cliConnMgr       The parent CliConnMgr instance managing this object
 * @param cliStore         The client's X.509 certificates store
 */
CliSTSMMgr::CliSTSMMgr(EVP_PKEY* myRSALongPrivKey, CliConnMgr& cliConnMgr, X509_STORE* cliStore)
                      : STSMMgr(myRSALongPrivKey), _stsmCliState(INIT), _cliConnMgr(cliConnMgr), _cliStore(cliStore)
 {}


/* ============================ OTHER PUBLIC METHODS ============================ */



//
//vector<unsigned char> ecdhPubkeyData(EVP_PKEY *key)
// {
//  int len = i2d_PublicKey(key, 0); // with 0 as second arg it gives length
//  vector<unsigned char> ret(len);
//  unsigned char *ptr = ret.data();
//  len = i2d_PublicKey(key, &ptr);
//  return ret;
// }


void CliSTSMMgr::recvSTSMMsg()
 {
  // Receive a full block
  _cliConnMgr.recvBlock();

  // Ensure that the data received consists of a valid STSM message
  checkCliSTSMError();
 }


void CliSTSMMgr::send_client_hello()
 {
  // Ensure that the STSM protocol was not already started by the manager
  if(_stsmCliState != INIT)
   THROW_SCODE(ERR_STSM_CLI_ALREADY_STARTED);

  // Interpret the connection manager's primary buffer as a 'CLIENT_HELLO' STSM message
  STSM_Client_Hello* cliHello = reinterpret_cast<STSM_Client_Hello*>(_cliConnMgr._priBuf);

  // Set the STSM message type
  cliHello->header.type = CLIENT_HELLO;


  // Initialize a memory BIO for extracting the client's ephemeral DH public key
  BIO* myPubDHBio = BIO_new(BIO_s_mem());

  // Write the client's ephemeral public DH key to the BIO
  PEM_write_bio_PUBKEY(myPubDHBio, _myDHEKey);

  // Write the client's ephemeral public DH key from the BIO into the 'Client_Hello' message
  // read the key from the buffer and put it in the char reference
  BIO_read(myPubDHBio, cliHello->cliPubKey, DH2048_PUBKEY_PEM_SIZE);


  // Generate a random AES_GCM IV
  _cliConnMgr._iv = new IVMgr();


  // Copy the generated IV into the CLIENT_HELLO message
  cliHello->iv = *_cliConnMgr._iv;


  // Increment the IV in the message (as on the client it will be incremented upon sending the message)
  cliHello->iv.incIV();


  // Set the total message length
  cliHello->header.len = sizeof(STSM_Client_Hello);


  // Send the message
  _cliConnMgr.sendData();

  LOG_DEBUG("STSM (1/4): Sent CLIENT_HELLO Message, awaiting SRV_AUTH message")

  // TODO Debug
  // Print the message's contents
  std::cout << "cliHello.header.len = " << cliHello->header.len << std::endl;
  std::cout << "cliHello.header.type = " << cliHello->header.type << std::endl;
  std::cout << "cliHello.iv.iv_high = " << cliHello->iv.iv_high << std::endl;
  std::cout << "cliHello.iv.iv_low = " << cliHello->iv.iv_low << std::endl;



  // Print the client's public key
  BIO* bp = BIO_new_fp(stdout, BIO_NOCLOSE);
  if(!EVP_PKEY_print_public(bp, _myDHEKey, 1, NULL))
   {
    std::cout << "error 5" << std::endl;
   }
  std::cout << bp <<std::endl;
  BIO_free(bp);



  // Free the BIO
  BIO_free(myPubDHBio);

 }





void CliSTSMMgr::startSTSM()
 {
  std::cout << "CliSTSMMgr: STARTING STSM" << std::endl;

  // Send the 'CLIENT_HELLO' STSM message
  send_client_hello();

  // Update the STSM client state
  _stsmCliState = WAITING_SRV_AUTH;

  // Receive the (supposedly) server's authentication message


 }


/*  for(int i = 0; i < 100; i++)
  {
   _myDHEKey = DHE_2048_Keygen();

   // extract public key as string
   // create a place to dump the IO, in this case in memory
   BIO* publicBIO = BIO_new(BIO_s_mem());

   // dump key to IO
   PEM_write_bio_PUBKEY(publicBIO, _myDHEKey);

   // get buffer length
   int publicKeyLen = BIO_pending(publicBIO);

   std::cout << "publicKeyLen = " << publicKeyLen << std::endl;

   // create char reference of public key length
   unsigned char* publicKeyChar = (unsigned char *) malloc(publicKeyLen);

   // read the key from the buffer and put it in the char reference
   BIO_read(publicBIO, publicKeyChar, publicKeyLen);

   //std::cout << "publicKeyChar = " << publicKeyChar << std::endl;
  }*/


// OLD ATTEMPT
/*  EVP_PKEY_print_public(BIO *out, const EVP_PKEY *pkey,
  int indent, ASN1_PCTX *pctx);

  std::cout << "_myDHKEKey = " << _myDHEKey << std::endl;

  // [with 0 as second arg it gives length] IT MUST BE NON-NEGATIVE
  int len = i2d_PublicKey(_myDHEKey, 0);

  std::cout << "len = " << len << std::endl;

  unsigned char* pubkeyPnt = (_cliConnMgr._priBuf) + 16;

  len = i2d_PublicKey(_myDHEKey,&pubkeyPnt);

  std::cout << "len = " << len << std::endl;*/