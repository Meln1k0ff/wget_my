#ifndef CONNECT_H
#define CONNECT_H

#include "wget.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int connect_to_host (const char *, int);
int fd_read (int, char *, int);
int fd_write (int, char *, int, double);
void fd_close (int fd);




#endif // CONNECT_H
