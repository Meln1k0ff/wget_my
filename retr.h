#ifndef RETR_H
#define RETR_H

#include <stdbool.h>
#include "url.h"
#include "iri.h"

int retrieve_url (struct url * orig_parsed, const char *origurl, char **file,
              char **newloc, const char *refurl, int *dt, bool recursive,
              struct iri *iri, bool register_status);


#endif // RETR_H
