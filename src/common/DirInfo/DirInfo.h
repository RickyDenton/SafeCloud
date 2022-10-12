#ifndef SAFECLOUD_DIRINFO_H
#define SAFECLOUD_DIRINFO_H

/*
 * This class represents a snapshot of the files (names +
 * metadata) within a directory (subdirectories excluded)
 */

/* ================================== INCLUDES ================================== */
#include <string.h>
#include<forward_list>
#include <dirent.h>
#include "errCodes/execErrCodes/execErrCodes.h"
#include "DirInfo/FileInfo/FileInfo.h"

/* ============================= TYPES DECLARATIONS ============================= */

class DirInfo
 {
  public:

   /* ================================= ATTRIBUTES ================================= */
   std::string* dirPath;                  // The directory's absolute path
   std::forward_list<FileInfo> dirFiles;  // The list of files (names + metadata) within the directory

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  DirInfo object constructor, creating a snapshot of the files (names + metadata) within a directory
    * @param  dirAbspath The absolute path of the directory to create the snapshot of
    * @throws ERR_DIR_OPEN_FAILED       The target directory was not found
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading a file's metadata
    */
   explicit DirInfo(std::string* dirAbspath);

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /**
    * @brief  Returns the number of files in the directory
    * @return The number of files in the directory
    */
   unsigned int numFiles();

   /**
    * @brief  Prints the indented name and metadata of all files in the directory, if any
    * @return 'true' if at least one file was printed or 'false' if the directory is empty
    */
   bool printDirContents();
 };


#endif //SAFECLOUD_DIRINFO_H