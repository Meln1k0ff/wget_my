#ifndef URL_H
#define URL_H

#include <stdbool.h>
#include "iri.h"

//supports only HTTP
enum url_scheme {
  SCHEME_HTTP,
  SCHEME_INVALID
};

enum {
  scm_disabled = 1,
  scm_has_query = 4,            /* whether scheme has ?query */
  scm_has_fragment = 8          /* whether scheme has #fragment */
};

struct scheme_data
{
  /* Short name of the scheme. */
  const char *name;
  /* Leading string that identifies the scheme". */
  const char *leading_string;
  /* Default port of the scheme when none is specified. */
  int default_port;
  /* Various flags. */
  int flags;
};

static struct scheme_data supported_schemes[] =
{
  { "http",     "http://",  80,  scm_has_query|scm_has_fragment }
};

/* Structure containing info on a URL.  */
struct url
{
  char *url;                /* Original URL */
  enum url_scheme scheme;   /* URL scheme */

  char *host;               /* Extracted hostname */
  int port;                 /* Port number */

  /* URL components (URL-quoted). */
  char *path;
  char *params;
  char *query;
  char *fragment;

  /* Extracted path info (unquoted). */
  char *dir;
  char *file;

  /* Username and password (unquoted). */
//  char *user;
//  char *passwd;
};

bool url_has_scheme (const char *url);
enum url_scheme url_scheme (const char *url);
char *uri_merge (const char *base, const char *link);
char *url_full_path (const struct url *);
char *rewrite_shorthand_url (const char *);
int scheme_default_port (enum url_scheme);

struct url * url_parse (const char *url, struct iri *iri);
void url_free (struct url *url);
#endif // URL_H
