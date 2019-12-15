#ifndef HOST_H
#define HOST_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "options.h"

#define IP_INADDR_DATA(x) ((void *) &(x)->data)

struct url;
struct address_list;

enum {
    LH_SILENT  = 1,
    LH_BIND    = 2,
    LH_REFRESH = 4
};

typedef struct {
  /* Address family, one of AF_INET or AF_INET6. */
  //int family;

  /* The actual data, in the form of struct in_addr or in6_addr: */
  union {
    struct in_addr d4;      /* IPv4 address */
  } data;

} ip_address;

struct options opt;


#endif // HOST_H
