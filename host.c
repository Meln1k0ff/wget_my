#include "host.h"
#include "options.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define SET_H_ERRNO(err) ((void)(h_errno = (err)))

struct address_list {
  int count;                    /* number of adrresses */
  ip_address *addresses;        /* pointer to the string of addresses */

  int faulty;                   /* number of addresses known not to work. */
  bool connected;               /* whether we were able to connect to
                                   one of the addresses in the list,
                                   at least once. */

  int refcount;                 /* reference count; when it drops to
                                   0, the entry is freed. */
};

struct ghbnwt_context {
  const char *host_name;
  struct hostent *hptr;
};

static void
gethostbyname_with_timeout_callback (void *arg)
{
  struct ghbnwt_context *ctx = (struct ghbnwt_context *)arg;
  ctx->hptr = gethostbyname (ctx->host_name);
}

static struct hostent *
gethostbyname_with_timeout (const char *host_name, double timeout)
{
  struct ghbnwt_context ctx;
  ctx.host_name = host_name;
  if (run_with_timeout (timeout, gethostbyname_with_timeout_callback, &ctx))
    {
      SET_H_ERRNO (HOST_NOT_FOUND);
      errno = ETIMEDOUT;
      return NULL;
    }
  if (!ctx.hptr)
    errno = 0;
  return ctx.hptr;
}

/* Print error messages for host errors.  */
static const char *
host_errstr (int error)
{
  /* Can't use switch since some of these constants can be equal,
     which makes the compiler complain about duplicate case
     values.  */
  if (error == HOST_NOT_FOUND
      || error == NO_RECOVERY
      || error == NO_DATA
      || error == NO_ADDRESS)
    return "Unknown host";
  else if (error == TRY_AGAIN)
    /* Message modeled after what gai_strerror returns in similar
       circumstances.  */
    return "Temporary failure in name resolution";
  else
    return "Unknown error";
}


static struct address_list *
address_list_from_ipv4_addresses (char **vec)
{
  int count, i;
  struct address_list *al = calloc(1, sizeof(struct address_list));

  count = 0;
  while (vec[count])
    ++count;
//  assert (count > 0);
//malloc ((len) * sizeof (type)
  al->addresses = malloc (sizeof(struct address_list));//one element only
  al->count     = count;
  al->refcount  = 1;

//  for (i = 0; i < count; i++)
//    {
//      ip_address *ip = &al->addresses[i];
//      ip->family = AF_INET;
//      memcpy (IP_INADDR_DATA (ip), vec[i], 4);
//    }

  return al;
}





struct address_list *
lookup_host (const char *host, int flags)
{
  struct address_list *al;
  bool silent = !!(flags & LH_SILENT);  
  bool numeric_address = false;
  double timeout = 5000; //set to 5000 ms

  /* If we're not using getaddrinfo, first check if HOST specifies a
     numeric IPv4 address.  Some implementations of gethostbyname
     (e.g. the Ultrix one and possibly Winsock) don't accept
     dotted-decimal IPv4 addresses.  */
  {
    uint32_t addr_ipv4 = (uint32_t)inet_addr (host);
    if (addr_ipv4 != (uint32_t) -1)
      {
        /* No need to cache host->addr relation, just return the
           address.  */
        char *vec[2];
        vec[0] = (char *)&addr_ipv4;
        vec[1] = NULL;
        return address_list_from_ipv4_addresses (vec);
      }
  }

  /* No luck with the cache; resolve HOST. */

  if (!numeric_address)
    {
      char *str = NULL, *name;

      if (opt.enable_iri && (name = idn_decode ((char *) host)) != NULL)
        {
          str = printf ("%s (%s)", name, host);
          free (name);
        }
      free (str);
    }


/* not ENABLE_IPV6 */
    {
      struct hostent *hptr = gethostbyname_with_timeout (host, timeout);
      if (!hptr)
        {
//          if (!silent)
//            {
//              if (errno != ETIMEDOUT)
//                logprintf (LOG_VERBOSE, _ ("failed: %s.\n"),
//                           host_errstr (h_errno));
//              else
//                logputs (LOG_VERBOSE, _ ("failed: timed out.\n"));
//            }
          return NULL;
        }
      /* Do older systems have h_addr_list?  */
      al = address_list_from_ipv4_addresses (hptr->h_addr_list);
    }
/* not ENABLE_IPV6 */

  /* Print the addresses determined by DNS lookup, but no more than
     three if show_all_dns_entries is not specified.  */
  if (!silent && !numeric_address)
    {
      int i;
      int printmax = al->count;

      if (!opt.show_all_dns_entries && printmax > 1)
          printmax = 1;

//      for (i = 0; i < printmax; i++)
//        {
          printf(print_address (al->addresses));
//          if (i < printmax - 1)
//            logputs (LOG_VERBOSE, ", ");
        }
//      if (printmax != al->count)
//        logputs (LOG_VERBOSE, ", ...");
//      logputs (LOG_VERBOSE, "\n");
//    }

  /* Cache the lookup information. */
//  if (use_cache)
//    cache_store (host, al);

  return al;
}
