#ifndef SAFECLOUD_FILEMETA_H
#define SAFECLOUD_FILEMETA_H

/* This class represents the subset of file metadata of interest for the SafeCloud application */

class FileMeta
 {
  private:

   /* =============================== PRIVATE METHODS =============================== */

   /**
    * @brief   Stringyfies the raw file size into a
    *          "size_value||size_unit" string, with:\n\n
    *             - "size_value" ranging between [0,9999]\n\n
    *             - "size_unit" consisting either in "B", "KB", "MB" or "GB"
    * @throws ERR_FILE_TOO_LARGE The file is too large (> 9999GB)
    */
   void rawSizeToStr();


   /**
    * @brief Stringyfies a raw time in Unix epochs into a
    *        destination buffer as a "HH:MM:SS DD/MM/YY" string
    * @param rawTime     The raw time in Unix Epochs
    * @param destBuf     The destination buffer address
    * @param destBufSize The destination buffer size
    */
   static void rawTimeToStr(signed long rawTime, char* destBuf);

  public:

   /* ================================= ATTRIBUTES ================================= */

   /* ----------------------------- Raw File Metadata ----------------------------- */

   /*
    * NOTE: While inherently positive, these attributes are represented
    *       on long integers for compatibility with the "stat.h" library
    */
   long int fileSizeRaw;      // The file size in bytes (max 9999GB)
   long int lastModTimeRaw;   // The file last modification time in UNIX epochs
   long int creationTimeRaw;  // The file creation time in UNIX epochs

   /* ------------------------- Stringifyed File Metadata ------------------------- */

   // The file size as a "size_value||size_unit" string, with:\n
   //    - "size_value" ranging between [0,9999]\n
   //    - "size_unit" consisting either in "B", "KB", "MB" or "GB"\n
   char fileSizeStr[7];

   // The file's last modified time as a "HH:MM:SS DD/MM/YY" string
   char lastModTimeStr[18];

   // The file's creation time as a "HH:MM:SS DD/MM/YY" string
   char creationTimeStr[18];

   /* ================================ CONSTRUCTOR ================================ */

   /**
    * @brief  fileMetadata values constructor, initializing its raw attributes to the
    *         provided values and its stringifyed attributes to their stringifyed versions
    * @param  fileSizeRaw_     The raw file size in bytes
    * @param  lastModTimeRaw_  The raw file last modified time in Unix Epochs
    * @param  creationTimeRaw_ The raw file creation time in Unix Epochs
    * @throws ERR_SESS_FILE_META_NEGATIVE Negative metadata values were provided
    * @throws ERR_FILE_TOO_LARGE          The file is too large (> 9999GB)
    */
   FileMeta(long int fileSizeRaw_, long int lastModTimeRaw_, long int creationTimeRaw_);

   /* ============================ OTHER PUBLIC METHODS ============================ */

   /**
    * @brief Prints the stringifyed file size to stdout, possibly formatted by:\n\n
    *          - Adding padding so to be aligned beneath a 'SIZE' table header\n\n
    *          - Printing it in bold
    * @param addPadding Whether padding should be added to the file size
    * @param printBold  Whether the file size should be printed in bold
    */
   void printFormattedSize(bool addPadding, bool printBold) const;

   /**
    * @brief Prints the stringifyed file's last
    *        modification time to stdout, possibly in bold
    * @param printBold Whether to print the stringifyed
    *                  file's last modification time in bold
    */
   void printFormattedLastModTime(bool printBold) const;

   /**
    * @brief Prints the stringifyed file's creation
    *        time to stdout, possibly in bold
    * @param printBold Whether to print the stringifyed
    *        file's creation time in bold
    */
   void printFormattedCreationTime(bool printBold) const;
 };


#endif //SAFECLOUD_FILEMETA_H
