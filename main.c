#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <ctype.h>

#include "url.h"
#include "retr.h"
#include "host.h"
#include "http.h"
#include "options.h"

//support only HTTP

const char *output_document = "index.html"; //where to write output

#define SCHEME_CHAR(ch) (isalnum (ch) || (ch) == '-' || (ch) == '+')
#define DEFAULT_HTTP_PORT 80

//string utils
static inline char *
strpbrk_or_eos (const char *s, const char *accept)
{
  char *p = strpbrk (s, accept);
  if (!p)
    p = strchr (s, '\0');
  return p;
}

char *
strdupdelim (const char *beg, const char *end)
{
  if (beg && beg <= end)
    {
      char *res = malloc (end - beg + 1);
      memcpy (res, beg, end - beg);
      res[end - beg] = '\0';
      return res;
    }

  return strdup("");
}






//////////////////////////////////////////////////////////////////////
/* Does FILENAME exist? */
//bool
//file_exists_p (const char *filename, file_stats_t *fstats)
//{
//  struct stat buf;

//  if (!filename)
//	  return false;
//  errno = 0;
//  if (stat (filename, &buf) == 0 && S_ISREG(buf.st_mode) &&
//              (((S_IRUSR & buf.st_mode) && (getuid() == buf.st_uid))  ||
//               ((S_IRGRP & buf.st_mode) && group_member(buf.st_gid))  ||
//                (S_IROTH & buf.st_mode))) {
//    if (fstats != NULL)
//    {
//      fstats->access_err = 0;
//      fstats->st_ino = buf.st_ino;
//      fstats->st_dev = buf.st_dev;
//    }
//    return true;
//  }
//  else
//  {
//    if (fstats != NULL)
//      fstats->access_err = (errno == 0 ? EACCES : errno);
//    errno = 0;
//    return false;
//  }
//  /* NOTREACHED */

//}

/* The genuine HTTP loop!  This is the part where the retrieval is
   retried, and retried, and retried, and...  */


int main(int argc, char *argv[])
{
    const char *urlname = argv[1];
    char *filename = NULL;
    char **t;
    char *redirected_URL = NULL;
    FILE *output = fopen(output_document, "w");
    struct url *url_parsed;
    struct iri *iri;
    int dt;
    if (argc < 2)
    {
      printf("Wrong args \n");
    }
    else
    {
       // set_uri_encoding (iri, opt.locale, true); only ASCII
        url_parsed = url_parse(urlname, iri);
        if (url_parsed)
        {
            retrieve_url (url_parsed, *t, &filename, &redirected_URL, NULL,
                                      &dt, false, iri, true);
            free(redirected_URL);
            free(filename);
            url_free (url_parsed);
        }
        else
        {
            printf("Broken URL \n");
        }
        printf("%s", url_parsed->path);
        //make request

    }
    fclose(output);

    return 0;
}
