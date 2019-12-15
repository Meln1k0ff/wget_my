#ifndef HTTP_H
#define HTTP_H
#include <stdbool.h>
#include <time.h>

#include "url.h"
#include "host.h"

struct http_stat
{
  int len;                    /* received length */
  int contlen;                /* expected length */
  int restval;                /* the restart value */
  int res;                      /* the result of last read */
  char *rderrmsg;               /* error message from read error */
  char *newloc;                 /* new location (redirection) */
  char *remote_time;            /* remote time-stamp string */
  char *error;                  /* textual HTTP error */
  int statcode;                 /* status code */
  char *message;                /* status message */
  int rd_size;                /* amount of data read from socket */
  const char *referer;          /* value of the referer header. */
  char *local_file;             /* local file name. */
  bool existence_checked;       /* true if we already checked for a file's
                                   existence after having begun to download
                                   (needed in gethttp for when connection is
                                   interrupted/restarted. */
  char *orig_file_name;         /* name of file to compare for time-stamping
                                 * (might be != local_file if -K is set) */
  int orig_file_size;         /* size of file to compare for time-stamping */
  time_t orig_file_tstamp;      /* time-stamp of file to compare for
                                 * time-stamping */
//  encoding_t local_encoding;    /* the encoding of the local file */
 // encoding_t remote_encoding;   /* the encoding of the remote file */

  bool temporary;               /* downloading a temporary file */
};

int http_loop (const struct url *u, struct url *original_url, char **newloc,
           char **local_file, const char *referer, int *dt, /*struct url *proxy,*/
           struct iri *iri);


#endif // HTTP_H
