#ifndef SAFECLOUD_SCOLORS_H
#define SAFECLOUD_SCOLORS_H

/* ANSI color codes for output formatting purposes */

#define RESET "\u001b[0m"   // Resets to default

/* ================= STANDARD COLORS ================= */
#define BLACK   "\e[0;30m"
#define RED     "\e[0;31m"
#define GREEN   "\e[0;32m"
#define YELLOW  "\e[0;33m"
#define BLUE    "\e[0;34m"
#define MAGENTA "\e[0;35m"
#define CYAN    "\e[0;36m"
#define WHITE   "\e[0;37m"

/* ================== BRIGHT COLORS ================== */
#define BRIGHTBLACK   "\e[0;90m"
#define BRIGHTRED     "\e[0;91m"
#define BRIGHTGREEN   "\e[0;92m"
#define BRIGHTYELLOW  "\e[0;93m"
#define BRIGHTBLUE    "\e[0;94m"
#define BRIGHTMAGENTA "\e[0;95m"
#define BRIGHTCYAN    "\e[0;96m"
#define BRIGHTWHITE   "\e[0;97m"

// TODO: REMOVE
/*#define BRIGHTBLACK "\u001b[30;1m"
#define BRIGHTRED "\u001b[30;1m"
#define BRIGHTGREEN "\u001b[30;1m"
#define BRIGHTYELLOW "\u001b[30;1m"
#define BRIGHTBLUE "\u001b[30;1m"
#define BRIGHTMAGENTA "\u001b[30;1m"
#define BRIGHTCYAN "\u001b[30;1m"
#define BRIGHTWHITE "\u001b[30;1m"*/


/* =================== BOLD COLORS =================== */
#define BOLDBLACK   "\e[1;30m"
#define BOLDRED     "\e[1;31m"
#define BOLDGREEN   "\e[1;32m"
#define BOLDYELLOW  "\e[1;33m"
#define BOLDBLUE    "\e[1;34m"
#define BOLDMAGENTA "\e[1;35m"
#define BOLDCYAN    "\e[1;36m"
#define BOLDWHITE   "\e[1;37m"

// TODO: REMOVE
/*#define BOLDBLACK   "\033[1m \033[30m"
#define BOLDRED     "\033[1m \033[31m"
#define BOLDGREEN   "\033[1m \033[32m"
#define BOLDYELLOW  "\033[1m \033[33m"
#define BOLDBLUE    "\033[1m \033[34m"
#define BOLDMAGENTA "\033[1m \033[35m"
#define BOLDCYAN    "\033[1m \033[36m"
#define BOLDWHITE   "\033[1m \033[37m"*/

/* =============== BOLD BRIGHT COLORS =============== */
#define BOLDBRIGHTBLACK   "\e[1;90m"
#define BOLDBRIGHTRED     "\e[1;91m"
#define BOLDBRIGHTGREEN   "\e[1;92m"
#define BOLDBRIGHTYELLOW  "\e[1;93m"
#define BOLDBRIGHTBLUE    "\e[1;94m"
#define BOLDBRIGHTMAGENTA "\e[1;95m"
#define BOLDBRIGHTCYAN    "\e[1;96m"
#define BOLDBRIGHTWHITE   "\e[1;97m"

#endif //SAFECLOUD_SCOLORS_H
