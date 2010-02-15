/* Types, as BYTE, WORD, DWORD      */

typedef enum {Error_ = -1, Success_, False_ = 0, True_} Boolean_T;

#if !defined(WIN32) && !defined(_WIN32) && !defined(__NT__) \
      && !defined(_WINDOWS)
 #if !defined(OS2)
  typedef unsigned char  BYTE;
  typedef unsigned long  DWORD;
 #endif
 typedef unsigned short WORD;
#else
 #define WIN32_LEAN_AND_MEAN
 #define NOGDI
 #define NOSERVICE
 #undef INC_OLE1
 #undef INC_OLE2
 #include <windows.h>
 #define HUGE
#endif
