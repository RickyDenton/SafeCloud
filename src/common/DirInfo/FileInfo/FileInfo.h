#ifndef SAFECLOUD_FILEINFO_H
#define SAFECLOUD_FILEINFO_H

/* This class represents a snapshot of a file (name + metadata) within a directory */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>
#include "DirInfo/FileInfo/FileMeta/FileMeta.h"


class FileInfo
 {
  public:

   /* ================================= ATTRIBUTES ================================= */
   std::string fileName; // The file name (with no directory path)
   FileMeta*   meta;     // The file metadata

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  FileInfo object path constructor, initializing the
    *         file name and metadata from its absolute path
    * @param  fileAbsPath The file's absolute path
    * @throws ERR_SESS_FILE_INVALID_NAME  Invalid Linux file name
    * @throws ERR_SESS_FILE_READ_FAILED   Error in reading the file's metadata
    * @throws ERR_SESS_FILE_IS_DIR        The file is in fact a directory
    * @throws ERR_SESS_FILE_META_NEGATIVE The file presents negative metadata values
    * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
    */
   explicit FileInfo(const std::string& fileAbsPath);

   /**
    * @brief  FileInfo object values constructor, initializing its attributes
    *         to the provided values
    * @param  fileName_     The file's name
    * @param  fileSize_     The file's size
    * @param  lastModTime_  The file's last modification time
    * @param  creationTime_ The file's creation time
    * @note   Conversely from the object path constructor, this constructor does
    *         not verify whether such a file exists in the local file system
    * @throws ERR_SESS_FILE_INVALID_NAME  Invalid Linux file name
    * @throws ERR_SESS_FILE_META_NEGATIVE The file presents negative metadata values
    * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
    */
   FileInfo(std::string& fileName_, long int fileSize_, long int lastModTime_, long int creationTime_);

   /**
    * @brief FileInfo object destructor, deleting the file's metadata
    */
   ~FileInfo();

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /* --------------------------- File Metadata Printing --------------------------- */

   /**
    * @brief Prints the file size as a "size_value||size_unit" string, with:\n
    *          - "size_value" ranging between [0,9999]\n
    *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"\n
    *        The file size can also be formatted by:
    *          - Adding padding so to be aligned beneath a 'SIZE' table header
    *          - Printing it in bold
    * @param addPadding Whether padding should be added to the file size
    * @param printBold  Whether the file size should be printed in bold
    */
   void printFormattedSize(bool addPadding, bool printBold) const;

   /**
    * @brief Prints the file's last modification time as a
    *        "HH:MM:SS DD/MM/YY" string, possibly in bold
    * @param printBold Whether to print the file's
    *                  last modification time in bold
    */
   void printFormattedLastModTime(bool printBold) const;

   /**
    * @brief Prints the file's creation time as a
    *        "HH:MM:SS DD/MM/YY" string, possibly in bold
    * @param printBold Whether to print the file's
    *                  creation time in bold
    */
   void printFormattedCreationTime(bool printBold) const;

   /* ----------------------------- File-Wide Printing ----------------------------- */

   /**
    * @brief Prints the indented file's name and metadata on stdout
    */
   void printFileInfo() const;

   /**
    * @brief  Prints a table comparing the metadata of the FileInfo (or 'local file') object
    *         with another FileInfo (or 'remote file') object with the same 'fileName'
    * @param  remFileInfo The FileInfo associated with the remote file
    * @throws ERR_FILEINFO_COMP_NULL       NULL 'remFileInfo' argument
    * @throws ERR_FILEINFO_COMP_DIFF_NAMES The two files have different names
    */
   void compareMetadata(FileInfo* remFileInfo) const;
 };


#endif //SAFECLOUD_FILEINFO_H