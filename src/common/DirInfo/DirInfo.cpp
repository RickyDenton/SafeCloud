/* DirInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "DirInfo.h"

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief  DirInfo object constructor, creating a snapshot of the files (names + metadata) within a directory
 * @param  dirAbspath The absolute path of the directory to create the snapshot of
 * @throws ERR_DIR_OPEN_FAILED  The target directory was not found
 * @throws ERR_FILE_READ_FAILED Error in reading a file's metadata
 */
DirInfo::DirInfo(std::string* dirAbspath) : dirPath(dirAbspath), dirFiles()
 {
  DIR*           dir;           // Target directory file descriptor
  struct dirent* dirFile;       // Information on a file in the target directory

  // Convert the directory path to a C string
  const char* dirPathC = dirPath->c_str();

  // Open the temporary directory
  dir = opendir(dirPathC);
  if(!dir)
   THROW_EXEC_EXCP(ERR_DIR_OPEN_FAILED, *dirPath, ERRNO_DESC);
  else
   {
    // For each file in the target directory
    while((dirFile = readdir(dir)) != NULL)
     {
      // Skip the directory and its parent's pointers
      if(!strcmp(dirFile->d_name, ".") || !strcmp(dirFile->d_name, ".."))
       continue;

      // Store the file's name and metadata in a FileInfo object
      dirFiles.emplace_front(FileInfo(*dirAbspath + '/' + std::string(dirFile->d_name)));
     }

    // Close the target directory
    if(closedir(dir) == -1)
     LOG_EXEC_CODE(ERR_DIR_CLOSE_FAILED, *dirPath, ERRNO_DESC);
   }
 }


/* ============================ OTHER PUBLIC METHODS ============================ */

/**
 * @brief  Returns the number of files in the directory
 * @return The number of files in the directory
 */
unsigned int DirInfo::numFiles()
 { return std::distance(dirFiles.begin(), dirFiles.end()); }


/**
 * @brief  Prints the indented metadata and name of all files in the directory, if any
 * @return 'true' if at least one file was printed or 'false' if the directory is empty
 */
bool DirInfo::printDirContents()
 {
  char fileSize[7];                 // The size of a file in the directory as a string
  unsigned char fileSizeIndBefore;  // The number of spaces to be printed before a file's size depending on its number of characters
  unsigned char fileSizeIndAfter;   // The number of spaces to be printed after a file's size depending on its number of characters
  char timeDate[18];                // A creation or last modified time value expressed as the string "HH:MM:SS DD/MM/YY"
  struct tm timeCalendar{};         // Stores a creation or last modification time in a calendar-like representation

  // If there are no files in the directory, just return
  if(numFiles() == 0)
   return false;

  // Otherwise, if the directory contains at least 1 file
  else
   {
    // Indentation
    printf("\n");

    // Print the file attribute's legend
    std::cout << " SIZE     CREATION TIME      LAST MODIFIED    FILE" << std::endl;
    std::cout << "---------------------------------------------------" << std::endl;

    // Print the attributes of each file in the directory
    for(const auto& it : dirFiles)
     {
      // Retrieve the file formatted size
      it.getFormattedSize(fileSize);

      // Determine the number of spaces to be printed before and
      // after the file's size depending on number of characters
      switch(strlen(fileSize))
       {
        // Minimum size characters (e.g. "9B")
        case 2:
         fileSizeIndBefore = 3;
         fileSizeIndAfter = 1;
         break;

        case 3:
         fileSizeIndBefore = 2;
         fileSizeIndAfter = 1;
         break;

        case 4:
         fileSizeIndBefore = 1;
         fileSizeIndAfter = 1;
         break;

        case 5:
         fileSizeIndBefore = 0;
         fileSizeIndAfter = 1;
         break;

        // Maximum size characters (e.g. "2467MB")
        case 6:
         fileSizeIndBefore = 0;
         fileSizeIndAfter = 0;
         break;

        // Unexpected number of characters
        default:
         LOG_CRITICAL("Unexpected file size string length: " + std::to_string(strlen(fileSize)))
         return true;
       }

      // Print the spaces before the file's size
       for(int i=0; i<fileSizeIndBefore; i++)
        printf(" ");

       // Print the file size
       printf("%s",fileSize);

      // Print the spaces after the file's size
      for(int i=0; i<fileSizeIndAfter; i++)
       printf(" ");

      // Indentation between the "SIZE" and "CREATION TIME" headers
      printf("  ");

      // Convert the file creation time from epochs to a calendar
      // form and print it as the string "HH:MM:SS DD/MM/YY"
      timeCalendar = *localtime(&it.fileMeta.creationTime);
      strftime(timeDate, sizeof(timeDate), "%H:%M:%S %d/%m/%y", &timeCalendar);
      printf("%s",timeDate);

      // Indentation between the "CREATION TIME" and "LAST MODIFIED" headers
      printf("  ");

      // Convert the file last modification time from epochs to a
      // calendar form and print it as the string "HH:MM:SS DD/MM/YY"
      timeCalendar = *localtime(&it.fileMeta.lastModTime);
      strftime(timeDate, sizeof(timeDate), "%H:%M:%S %d/%m/%y", &timeCalendar);
      printf("%s",timeDate);

      // Indentation between the "CREATION TIME" and "FILE" headers
      printf("  ");

      // Print the file name and a new line
      std::cout << it.fileName << std::endl;
     }

    // Indentation
    printf("\n");

    // Return that at least one file has been printed
    return true;
   }
 }