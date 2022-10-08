#ifndef SAFECLOUD_FILEINFO_H
#define SAFECLOUD_FILEINFO_H

/* This class represents a snapshot of a file (name + metadata) within a directory */

/* ================================== INCLUDES ================================== */
#include <iostream>
#include <ctime>
#include <sys/types.h>
#include <sys/stat.h>
#include <cstring>

/* ============================= TYPES DECLARATIONS ============================= */

/*
 * The subset of file metadata of interest for the SafeCloud application
 *
 * NOTE: While inherently positive, the "stat.h" library
 *       returns file metadata on signed integers
 */
struct fileMetadata
 {
  /* ================================= ATTRIBUTES ================================= */
  long int fileSize;      // The file size in bytes
  long int creationTime;  // The file creation time in UNIX epoch time
  long int lastModTime;   // The file last modification time in UNIX epoch time

  /* ================================ CONSTRUCTORS ================================ */

  /**
   * @brief fileMetadata default constructor, initializing its fields to "-1"
   */
  fileMetadata();

  /**
   * @brief fileMetadata object values constructor, initializing its fields to the provided values
   */
  fileMetadata(long int fileSize_, long int creationTime_, long int lastModTime_);
 };


class FileInfo
 {
  public:

   /* ================================= ATTRIBUTES ================================= */
   std::string fileName;    // File name (with no directory path)
   fileMetadata fileMeta;   // File metadata

   /* ========================= CONSTRUCTOR AND DESTRUCTOR ========================= */

   /**
    * @brief  FileInfo object constructor, initializing the file name and metadata
    * @param  dirAbsPath The absolute path of the directory the file is contained in
    * @param  fileName_  The file's name
    * @throws ERR_FILE_OPEN_FAILED Error in reading the file's metadata
    */
   FileInfo(std::string* dirAbsPath,std::string fileName);

  /* ============================ OTHER PUBLIC METHODS ============================ */

  /**
   * @brief  Writes in a buffer the file size formatted
   *         as the string "size_value||size_unit", with:
   *          - "size_value" ranging between [0,9999]
   *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"
   * @param  formSizeDest The buffer where to write the formatted file size
   * @note   This function assumes the destination buffer to be large
   *         enough to contain the formatted file size (at least 7 bytes)
   * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
   */
  void getFormattedSize(char* formSizeDest) const;

  /**
   * @brief  Reads and returns a file's metadata
   * @param  fileAbsPath The file's absolute path
   * @return A dynamic structure containing the file's metadata, or
   *         "nullptr" if the file does not exist or could not be opened
   * @note   It is up to the caller to delete() the returned struct when no longer needed
   */
  static fileMetadata* getFileMetadata(std::string* fileAbsPath);
 };


#endif //SAFECLOUD_FILEINFO_H