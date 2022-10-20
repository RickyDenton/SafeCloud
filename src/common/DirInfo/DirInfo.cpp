/* DirInfo class methods definitions */

/* ================================== INCLUDES ================================== */
#include "DirInfo.h"

/* ========================= CONSTRUCTORS AND DESTRUCTOR ========================= */

/**
 * @brief  DirInfo object constructor, creating a snapshot of the files (names + metadata) within a directory
 * @param  dirAbspath The absolute path of the directory to create the snapshot of
 * @throws ERR_DIR_OPEN_FAILED       The target directory was not found
 * @throws ERR_SESS_FILE_READ_FAILED Error in reading a file's metadata
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
      // Skip the directory itself, the pointer to the parent's directory, and subdirectories
      if(!strcmp(dirFile->d_name, ".") || !strcmp(dirFile->d_name, "..") || dirFile->d_type == DT_DIR)
       continue;

      // Store the file's name and metadata in a FileInfo object
      dirFiles.emplace_front(new FileInfo(*dirAbspath + '/' + std::string(dirFile->d_name)));
     }

    // Close the target directory
    if(closedir(dir) == -1)
     LOG_EXEC_CODE(ERR_DIR_CLOSE_FAILED, *dirPath, ERRNO_DESC);
   }
 }


/**
 * @brief DirInfo object destructor, deleting the list of FileInfo objects
 */
DirInfo::~DirInfo()
 {
  for(FileInfo* fileInfo : dirFiles)
   delete fileInfo;
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
  // If there are no files in the directory, just return
  if(numFiles() == 0)
   return false;

   // Otherwise, if the directory contains at least 1 file
  else
   {
    // Indentation
    printf("\n");

    // Print the files attributes' legend
    std::cout << " SIZE     LAST MODIFIED      CREATION TIME    FILE" << std::endl;
    std::cout << "---------------------------------------------------" << std::endl;

    // Print the attributes of each file in the directory
    for(const auto& it : dirFiles)
     {
      // Print the file size with padding spaces
      it->printFormattedSize(true, false);

      // Indentation between the "SIZE" and "LAST MODIFIED" headers
      printf("  ");

      // Print the file last modification time
      it->printFormattedLastModTime(false);

      // Indentation between the "LAST MODIFIED and "CREATION TIME" headers
      printf("  ");

      // Print the file creation time
      it->printFormattedCreationTime(false);

      // Indentation between the "CREATION TIME" and "FILE" headers
      printf("  ");

      // Print the file name and a new line
      std::cout << it->fileName << std::endl;
     }

    // Indentation
    printf("\n");

    // Return that at least one file has been printed
    return true;
   }
 }