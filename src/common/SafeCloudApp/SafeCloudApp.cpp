/* SafeCloud Application Abstract Class Definition */

/* ================================== INCLUDES ================================== */
#include "SafeCloudApp.h"


/* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

/**
 * @brief SafeCloudApp base constructor
 */
SafeCloudApp::SafeCloudApp()
 : _srvAddr(), _rsaKey(nullptr), _connected(false), _shutdown(false)
 {}

/**
 * @brief SafeCloudApp virtual destructor, making the class abstract
 */
SafeCloudApp::~SafeCloudApp()
 {}