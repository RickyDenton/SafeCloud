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
    * @brief  FileInfo object path constructor, initializing the
    *         file name and metadata from its absolute path
    * @param  fileAbsPath The file's absolute path
    * @throws ERR_SESS_FILE_READ_FAILED Error in reading the file's metadata
    * @throws ERR_SESS_FILE_IS_DIR      The file is in fact a directory
    */
   explicit FileInfo(const std::string& fileAbsPath);

   /**
    * @brief FileInfo object values constructor, initializing its attributes
    *        to the provided values
    * @param fileName_     The file's name
    * @param fileSize_     The file's size
    * @param creationTime_ The file's creation time
    * @param lastModTime_  The file's last modification time
    * @note  Conversely from the object path constructor, this constructor does
    *        not verify whether such a file exists in the local file system
    */
   FileInfo(std::string& fileName_, long int fileSize_, long int creationTime_, long int lastModTime_);

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /* ----------------------------- File Size Printing ----------------------------- */

   /**
    * @brief  Writes into a buffer the file size formatted
    *         as a "size_value||size_unit" string, with:\n
    *          - "size_value" ranging between [0,9999]\n
    *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"
    * @param  fileSizeStr The buffer where to write the formatted file size
    * @note   This function assumes the 'fileSizeStr' buffer to be large
    *         enough to contain the formatted file size (at least 7 bytes)
    * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
    */
   void sizeToStr(char* fileSizeStr) const;

   /**
    * @brief Prints the file size as a "size_value||size_unit" string, with:\n
    *          - "size_value" ranging between [0,9999]\n
    *          - "size_unit" consisting either in "B", "KB", "MB" or "GB"\n
    *        The file size can also be formatted by:
    *          - Adding padding so to be aligned beneath a 'SIZE' table header
    *          - Printing it in bold
    * @param addPadding Whether padding should be added to the file size
    * @param printBold  Whether the file size should be printed in bold
    * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
    */
   void printSize(bool addPadding, bool printBold) const;

   /* ---------------------------- File Times Printing ---------------------------- */

   /**
    * @brief Prints a time in Unix Epochs as a "HH:MM:SS DD/MM/YY" string, possibly in bold
    * @param timeEpochs The time in Unix Epochs
    * @param printBold  Whether the "HH:MM:SS DD/MM/YY" string should be printed in bold
    */
   static void printTime(signed long timeEpochs, bool printBold);

   /**
    * @brief Prints the file's last modification time as a
    *        "HH:MM:SS DD/MM/YY" string, possibly in bold
    * @param printBold Whether to print the file's
    *                  last modification time in bold
    */
   void printLastModTime(bool printBold) const;

   /**
    * @brief Prints the file's creation time as a
    *        "HH:MM:SS DD/MM/YY" string, possibly in bold
    * @param printBold Whether to print the file's
    *                  creation time in bold
    */
   void printCreationTime(bool printBold) const;

   /* -------------------------- Other Printing Utilities -------------------------- */

   /**
    * @brief Prints the indented file's name and metadata on stdout
    * @throws ERR_FILE_TOO_LARGE The file size is too large (> 9999GB)
    */
   void printInfo() const;

   /**
    * @brief Prints a table comparing the metadata of the FileInfo (or 'local file') object
    *        with another FileInfo (or 'remote file') object with the same 'fileName'
    * @param remFileInfo The FileInfo associated with the remote file
    * @throws ERR_FILEINFO_COMP_NULL       NULL 'remFileInfo' argument
    * @throws ERR_FILEINFO_COMP_DIFF_NAMES The two files have different names
    */
   void compareMetadata(FileInfo* remFileInfo) const;

  // TODO: Needed? In case, section
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