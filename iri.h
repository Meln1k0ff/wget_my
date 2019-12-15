#ifndef IRI_H
#define IRI_H

#include <stdbool.h>

struct iri {
  char *uri_encoding;      /* Encoding of the uri to fetch */
  char *content_encoding;  /* Encoding of links inside the fetched file */
  char *orig_url;          /* */
  bool utf8_encode;        /* Will/Is the current url encoded in utf8 */
};


const char *locale_to_utf8 (const char *str);
const char *find_locale (void);
char *idn_encode (const struct iri *i, const char *host);
char *idn_decode (const char *host);

#endif // IRI_H
