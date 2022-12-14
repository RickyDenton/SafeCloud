#ifndef SAFECLOUD_ANSI_COLORS_H
#define SAFECLOUD_ANSI_COLORS_H

/* List of ANSI colors used for severity-based error logging formatting */

#define RESET "\u001b[0m"    // Reset color to terminal default
#define BOLD  "\e[1m"        // BOLD, keep current color

/* ======  STANDARD COLORS ====== */
#define BLACK             "\e[0;30m"
#define RED               "\e[0;31m"
#define GREEN             "\e[0;32m"
#define YELLOW            "\e[0;33m"
#define BLUE              "\e[0;34m"
#define MAGENTA           "\e[0;35m"
#define CYAN              "\e[0;36m"
#define WHITE             "\e[0;37m"

/* ======== BRIGHT COLORS ======== */
#define BRIGHTBLACK       "\e[0;90m"
#define BRIGHTRED         "\e[0;91m"
#define BRIGHTGREEN       "\e[0;92m"
#define BRIGHTYELLOW      "\e[0;93m"
#define BRIGHTBLUE        "\e[0;94m"
#define BRIGHTMAGENTA     "\e[0;95m"
#define BRIGHTCYAN        "\e[0;96m"
#define BRIGHTWHITE       "\e[0;97m"

/* ======== BOLD COLORS ========== */
#define BOLDBLACK         "\e[1;30m"
#define BOLDRED           "\e[1;31m"
#define BOLDGREEN         "\e[1;32m"
#define BOLDYELLOW        "\e[1;33m"
#define BOLDBLUE          "\e[1;34m"
#define BOLDMAGENTA       "\e[1;35m"
#define BOLDCYAN          "\e[1;36m"
#define BOLDWHITE         "\e[1;37m"

/* ===== BOLD BRIGHT COLORS ===== */
#define BOLDBRIGHTBLACK   "\e[1;90m"
#define BOLDBRIGHTRED     "\e[1;91m"
#define BOLDBRIGHTGREEN   "\e[1;92m"
#define BOLDBRIGHTYELLOW  "\e[1;93m"
#define BOLDBRIGHTBLUE    "\e[1;94m"
#define BOLDBRIGHTMAGENTA "\e[1;95m"
#define BOLDBRIGHTCYAN    "\e[1;96m"
#define BOLDBRIGHTWHITE   "\e[1;97m"


#endif //SAFECLOUD_ANSI_COLORS_H