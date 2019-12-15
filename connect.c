#include "connect.h"

#include <assert.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>

#include "host.h"

int
connect_to_host (const char *host, int port)
{
  int i, start, end;
  int sock;
    //only for one address
  struct address_list *al = lookup_host (host, 0);

// address_list_get_bounds (al, &start, &end);
//  for (i = start; i < end; i++)
//    {
//

     const ip_address *ip = address_list_address_at (al, i);
      sock = connect_to_ip (ip, port, host);
//      if (sock >= 0)
//        {
//          /* Success. */
//          address_list_set_connected (al);
//          address_list_release (al);
//          return sock;
//        }

//      /* The attempt to connect has failed.  Continue with the loop
//         and try next address. */

//      address_list_set_faulty (al, i);
//    }

  /* Failed to connect to any of the addresses in AL. */

  if (address_list_connected_p (al))
    {
      /* We connected to AL before, but cannot do so now.  That might
         indicate that our DNS cache entry for HOST has expired.  */
      address_list_release (al);
      al = lookup_host (host, LH_REFRESH);
    //  goto retry;
    }
  address_list_release (al);

  return -1;
}

static int
sock_read (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = read (fd, buf, bufsize);
  while (res == -1 && errno == EINTR);
  return res;
}


//int fd_read (int fd, char *buf, int bufsize)
//{
//    return sock_read (fd, buf, bufsize);
//}



//int fd_write (int, char *, int, double)
//{

//}

static int
sock_write (int fd, char *buf, int bufsize)
{
  int res;
  do
    res = write (fd, buf, bufsize);
  while (res == -1 && errno == EINTR);
  return res;
}

void fd_close (int fd)
{
    close(fd);
}
