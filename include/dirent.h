#pragma once

typedef unsigned long int __ino_t;
typedef long int __off_t;

struct dirent {
    __ino_t d_ino;
    __off_t d_off;
    unsigned short int d_reclen;
    unsigned char d_type;
    char d_name[256];
};

#define d_fileno d_ino
#define _DIRENT_HAVE_D_RECLEN
#define _DIRENT_HAVE_D_OFF
#define _DIRENT_HAVE_D_TYPE
#define _DIRENT_MATCHES_DIRENT64 0
