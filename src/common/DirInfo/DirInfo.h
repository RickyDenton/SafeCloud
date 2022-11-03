#ifndef SAFECLOUD_DIRINFO_H
#define SAFECLOUD_DIRINFO_H

/*
 * This class represents a snapshot of the files (names +
 * metadata) within a directory (subdirectories excluded)
 */

/* ================================== INCLUDES ================================== */

// System Headers
#include <forward_list>

// SafeCloud Headers
#include "DirInfo/FileInfo/FileInfo.h"


class DirInfo
 {
  public:

   /* ================================= ATTRIBUTES ================================= */

   // The directory's absolute path
   std::string* dirPath;

   // The list of information (names + metadata) of files in the directory
   std::forward_list<FileInfo*> dirFiles;

   // The directory contents' raw size, consisting in the sum of its files names' lengths
   // ('\0' excluded) and their metadata (excluding the directory's absolute path)
   unsigned int dirRawSize;

   // The number of files in the directory
   unsigned int numFiles;

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief DirInfo empty constructor, creating an
    *        empty object of implicit directory path
    */
   DirInfo();

   /**
    * @brief  DirInfo absolute path constructor, creating a snapshot
    *         of the files (names + metadata) in a directory
    * @param  dirAbspath The absolute path of the directory to create the snapshot of
    * @throws ERR_DIR_OPEN_FAILED        The target directory was not found
    * @throws ERR_SESS_FILE_READ_FAILED  Error in reading a file's metadata
    * @throws ERR_SESS_DIR_INFO_OVERFLOW The directory information size exceeds 4GB
    */
   explicit DirInfo(std::string* dirAbspath);

   /**
    * @brief DirInfo object destructor, deleting the list of FileInfo objects
    */
   ~DirInfo();

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /**
    * @brief  Adds a file with its information in the directory
    * @param  fileInfo The information on the file to be added to the directory
    * @throws ERR_SESS_DIR_INFO_OVERFLOW The directory information size exceeds 4GB
    */
   void addFileInfo(FileInfo* fileInfo);

   /**
    * @brief  Prints the indented name and metadata of all files in the directory, if any
    * @return 'true' if at least one file was printed or 'false' if the directory is empty
    */
   bool printDirContents();
 };


#endif //SAFECLOUD_DIRINFO_H