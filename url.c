#include "url.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"

#define SCHEME_CHAR(ch) (isalnum (ch) || (ch) == '-' || (ch) == '+')


static inline char *
strpbrk_or_eos (const char *s, const char *accept)
{
  char *p = strpbrk (s, accept);
  if (!p)
    p = strchr (s, '\0');
  return p;
}

bool
url_has_scheme (const char *url)
{
  const char *p = url;

  /* The first char must be a scheme char. */
  if (!*p || !SCHEME_CHAR (*p))
    return false;
  ++p;
  /* Followed by 0 or more scheme chars. */
  while (*p && SCHEME_CHAR (*p))
    ++p;
  /* Terminated by ':'. */
  return *p == ':';
}

enum url_scheme
url_scheme (const char *url)
{
  int i;

  for (i = 0; supported_schemes[i].leading_string; i++)
    if (0 == strncasecmp (url, supported_schemes[i].leading_string,
                          strlen (supported_schemes[i].leading_string)))
      {
        if (!(supported_schemes[i].flags & scm_disabled))
          {
            printf("HTTP \n");
            return (enum url_scheme) i;
          }

        else
          return SCHEME_INVALID;
      }

  return SCHEME_INVALID;
}

char *
rewrite_shorthand_url (const char *url)
{
  const char *p;
  char *ret;

  if (url_scheme (url) != SCHEME_INVALID)
    return NULL;

  /* Look for a ':' or '/'.  The former signifies NcFTP syntax, the
     latter Netscape.  */
  p = strpbrk (url, ":/");
  if (p == url)
    return NULL;

  /* If we're looking at "://", it means the URL uses a scheme we
     don't support, which may include "https" when compiled without
     SSL support.  Don't bogusly rewrite such URLs.  */
  if (p && p[0] == ':' && p[1] == '/' && p[2] == '/')
    return NULL;

  if (p && *p == ':')
    {
      /* Colon indicates ftp, as in foo.bar.com:path.  Check for
         special case of http port number ("localhost:10000").  */
      int digits = strspn (p + 1, "0123456789");
      if (digits && (p[1 + digits] == '/' || p[1 + digits] == '\0'))
        goto http;

      /* Turn "foo.bar.com:path" to "ftp://foo.bar.com/path". */
      if ((ret = printf ("ftp://%s", url)) != NULL)
        ret[6 + (p - url)] = '/';
    }
  else
    {
    http:
      /* Just prepend "http://" to URL. */
      ret = printf ("http://%s", url);
    }
  return ret;
}

//DEFAULT_HTTP_PORT
int
scheme_default_port (enum url_scheme scheme)
{
  return supported_schemes[scheme].default_port;
}

const char *
init_separators (enum url_scheme scheme)
{
  static char seps[8] = ":/";
  char *p = seps + 2;
  int flags = supported_schemes[scheme].flags; //http only

  if (flags & scm_has_query)
    *p++ = '?';
  if (flags & scm_has_fragment)
    *p++ = '#';
  *p = '\0';
  return seps;
}

static int
full_path_length (const struct url *url)
{
  int len = 0;

  if (url->path) len += 1 + strlen (url->path);
  if (url->params) len += 1 + strlen (url->path);
  if (url->query) len += 1 + strlen (url->query);

  return len;
}

static void full_path_write(const struct url *url, char *path)
{
    char path_sep = "/";
    char param_sep = ";";
    char query_sep = "?";
    if (url->path)
    {
        do {
          char *f_el = url->path;
          if (f_el) {
            int l = strlen (f_el);
            *path++ = path_sep;
            memcpy (path, f_el, l);
            path += l;
          }
        } while (0);
    }
    if (url->params)
    {
        do {
          char *f_el = url->params;
          if (f_el) {
            int l = strlen (f_el);
            *path++ = param_sep;
            memcpy (path, f_el, l);
            path += l;
          }
        } while (0);
    }
    if (url->query)
    {
        do {
          char *f_el = url->query;
          if (f_el) {
            int l = strlen (f_el);
            *path++ = query_sep;
            memcpy (path, f_el, l);
            path += l;
          }
        } while (0);
    }
}

/* Public function for getting the "full path".  E.g. if u->path is
   "foo/bar" and u->query is "param=value", full_path will be
   "/foo/bar?param=value". */

char *
url_full_path (const struct url *url)
{
  int length = full_path_length (url);
  char *full_path = malloc (length + 1);

  full_path_write (url, full_path);
  full_path[length] = '\0';

  return full_path;
}



char *
uri_merge (const char *base, const char *link)
{
  int linklength;
  const char *end;
  char *merge;

  if (url_has_scheme (link))
    return xstrdup (link);

  /* We may not examine BASE past END. */
  end = path_end (base);
  linklength = strlen (link);

  if (!*link)
    {
      /* Empty LINK points back to BASE, query string and all. */
      return strdup (base);
    }
  else if (*link == '?')
    {
      /* LINK points to the same location, but changes the query
         string.  Examples: */
      /* uri_merge("path",         "?new") -> "path?new"     */
      /* uri_merge("path?foo",     "?new") -> "path?new"     */
      /* uri_merge("path?foo#bar", "?new") -> "path?new"     */
      /* uri_merge("path#foo",     "?new") -> "path?new"     */
      int baselength = end - base;
      merge = xmalloc (baselength + linklength + 1);
      memcpy (merge, base, baselength);
      memcpy (merge + baselength, link, linklength);
      merge[baselength + linklength] = '\0';
    }
  else if (*link == '#')
    {
      /* uri_merge("path",         "#new") -> "path#new"     */
      /* uri_merge("path#foo",     "#new") -> "path#new"     */
      /* uri_merge("path?foo",     "#new") -> "path?foo#new" */
      /* uri_merge("path?foo#bar", "#new") -> "path?foo#new" */
      int baselength;
      const char *end1 = strchr (base, '#');
      if (!end1)
        end1 = base + strlen (base);
      baselength = end1 - base;
      merge = xmalloc (baselength + linklength + 1);
      memcpy (merge, base, baselength);
      memcpy (merge + baselength, link, linklength);
      merge[baselength + linklength] = '\0';
    }
  else if (*link == '/' && *(link + 1) == '/')
    {
      /* LINK begins with "//" and so is a net path: we need to
         replace everything after (and including) the double slash
         with LINK. */

      /* uri_merge("foo", "//new/bar")            -> "//new/bar"      */
      /* uri_merge("//old/foo", "//new/bar")      -> "//new/bar"      */
      /* uri_merge("http://old/foo", "//new/bar") -> "http://new/bar" */

      int span;
      const char *slash;
      const char *start_insert;

      /* Look for first slash. */
      slash = memchr (base, '/', end - base);
      /* If found slash and it is a double slash, then replace
         from this point, else default to replacing from the
         beginning.  */
      if (slash && *(slash + 1) == '/')
        start_insert = slash;
      else
        start_insert = base;

      span = start_insert - base;
      merge = xmalloc (span + linklength + 1);
      if (span)
        memcpy (merge, base, span);
      memcpy (merge + span, link, linklength);
      merge[span + linklength] = '\0';
    }
  else if (*link == '/')
    {
      /* LINK is an absolute path: we need to replace everything
         after (and including) the FIRST slash with LINK.

         So, if BASE is "http://host/whatever/foo/bar", and LINK is
         "/qux/xyzzy", our result should be
         "http://host/qux/xyzzy".  */
      int span;
      const char *slash;
      const char *start_insert = NULL; /* for gcc to shut up. */
      const char *pos = base;
      bool seen_slash_slash = false;
      /* We're looking for the first slash, but want to ignore
         double slash. */
    again:
      slash = memchr (pos, '/', end - pos);
      if (slash && !seen_slash_slash)
        if (*(slash + 1) == '/')
          {
            pos = slash + 2;
            seen_slash_slash = true;
            goto again;
          }

      /* At this point, SLASH is the location of the first / after
         "//", or the first slash altogether.  START_INSERT is the
         pointer to the location where LINK will be inserted.  When
         examining the last two examples, keep in mind that LINK
         begins with '/'. */

      if (!slash && !seen_slash_slash)
        /* example: "foo" */
        /*           ^    */
        start_insert = base;
      else if (!slash && seen_slash_slash)
        /* example: "http://foo" */
        /*                     ^ */
        start_insert = end;
      else if (slash && !seen_slash_slash)
        /* example: "foo/bar" */
        /*           ^        */
        start_insert = base;
      else if (slash && seen_slash_slash)
        /* example: "http://something/" */
        /*                           ^  */
        start_insert = slash;

      span = start_insert - base;
      merge = xmalloc (span + linklength + 1);
      if (span)
        memcpy (merge, base, span);
      memcpy (merge + span, link, linklength);
      merge[span + linklength] = '\0';
    }
  else
    {
      /* LINK is a relative URL: we need to replace everything
         after last slash (possibly empty) with LINK.

         So, if BASE is "whatever/foo/bar", and LINK is "qux/xyzzy",
         our result should be "whatever/foo/qux/xyzzy".  */
      bool need_explicit_slash = false;
      int span;
      const char *start_insert;
      const char *last_slash = find_last_char (base, end, '/');
      if (!last_slash)
        {
          /* No slash found at all.  Replace what we have with LINK. */
          start_insert = base;
        }
      else if (last_slash && last_slash >= base + 2
               && last_slash[-2] == ':' && last_slash[-1] == '/')
        {
          /* example: http://host"  */
          /*                      ^ */
          start_insert = end + 1;
          need_explicit_slash = true;
        }
      else
        {
          /* example: "whatever/foo/bar" */
          /*                        ^    */
          start_insert = last_slash + 1;
        }

      span = start_insert - base;
      merge = xmalloc (span + linklength + 1);
      if (span)
        memcpy (merge, base, span);
      if (need_explicit_slash)
        merge[span - 1] = '/';
      memcpy (merge + span, link, linklength);
      merge[span + linklength] = '\0';
    }

  return merge;
}


struct url *
url_parse (const char *url, struct iri *iri)
{
  struct url *u;
  const char *p;
  bool path_modified, host_modified;

  enum url_scheme scheme;
  const char *seps;
  //start and end of identifiers
  const char *uname_b,     *uname_e;
  const char *host_b,      *host_e;
  const char *path_b,      *path_e;
  const char *params_b,    *params_e;
  const char *query_b,     *query_e;
  const char *fragment_b,  *fragment_e;

  int port;
//  char *user = NULL, *passwd = NULL;

  const char *url_encoded = NULL;

  int error_code;

  scheme = url_scheme (url); //return only http
  if (scheme == SCHEME_INVALID)
  {
    printf("url_scheme invalid \n");
    return NULL;
  }

  url_encoded = url;

  // if (iri && iri->utf8_encode)
  //   {
  //     char *new_url = NULL;
  //
  //     iri->utf8_encode = remote_to_utf8 (iri, iri->orig_url ? iri->orig_url : url, &new_url);
  //     if (!iri->utf8_encode)
  //       new_url = NULL;
  //     else
  //       {
  //         xfree (iri->orig_url);
  //         iri->orig_url = xstrdup (url);
  //         url_encoded = reencode_escapes (new_url);
  //         if (url_encoded != new_url)
  //           xfree (new_url);
  //         percent_encode = false;
  //       }
  //   }

//  if (percent_encode)
//    url_encoded = reencode_escapes (url);

  p = url_encoded;
  p += strlen (supported_schemes[scheme].leading_string);

  /* scheme://user:pass@host[:port]... */
  /*                    ^              */

  /* We attempt to break down the URL into the components path,
     params, query, and fragment.  They are ordered like this:

       scheme://host[:port][/path][;params][?query][#fragment]  */

  path_b     = path_e     = NULL;
  params_b   = params_e   = NULL;
  query_b    = query_e    = NULL;
  fragment_b = fragment_e = NULL;

  /* Initialize separators for optional parts of URL, depending on the
     scheme.  For example, FTP has params, and HTTP and HTTPS have
     query string and fragment. */
  seps = init_separators (scheme);

  host_b = p;

  p = strpbrk_or_eos (p, seps);
  host_e = p;

  printf("host_b = %s \n", host_b);

  ++seps;                       /* advance to '/' */

  if (host_b == host_e)
    {
      //error_code = PE_INVALID_HOST_NAME;
      //goto error;
      printf("error PE_INVALID_HOST_NAME\n");
    }

  port = scheme_default_port (scheme);  //?
  if (*p == ':')
    {
      const char *port_b, *port_e, *pp;

      /* scheme://host:port/tralala */
      /*              ^             */
      ++p;
      port_b = p;
      p = strpbrk_or_eos (p, seps);
      port_e = p;
      printf("port e %s \n",port_e);
      /* Allow empty port, as per rfc2396. */
      if (port_b != port_e)
        for (port = 0, pp = port_b; pp < port_e; pp++)
          {
            if (!isdigit (*pp))
              {
                /* http://host:12randomgarbage/blah */
                /*               ^                  */
               printf("PE_BAD_PORT_NUMBER \n");
//                goto error;
              }
            port = 10 * port + (*pp - '0');
            /* Check for too large port numbers here, before we have
               a chance to overflow on bogus port values.  */
            if (port > 0xffff)
              {
                printf("PE_BAD_PORT_NUMBER \n");
                //error_code = PE_BAD_PORT_NUMBER;
//                goto error;
              }
          }
    }
  /* Advance to the first separator *after* '/' (either ';' or '?',
     depending on the scheme).  */
  ++seps;

  /* Get the optional parts of URL, each part being delimited by
     current location and the position of the next separator.  */
 #define GET_URL_PART(sepchar, var) do {                         \
   if (*p == sepchar)                                            \
     var##_b = ++p, var##_e = p = strpbrk_or_eos (p, seps);      \
   ++seps;                                                       \
 } while (0)

  GET_URL_PART ('/', path);
  // if (supported_schemes[scheme].flags & scm_has_params)
  //   GET_URL_PART (';', params);
  // if (supported_schemes[scheme].flags & scm_has_query)
  //   GET_URL_PART ('?', query);
  // if (supported_schemes[scheme].flags & scm_has_fragment)
  //   GET_URL_PART ('#', fragment);
#undef GET_URL_PART
 // assert (*p == 0);

  // if (uname_b != uname_e)
  //   {
  //     /* http://user:pass@host */
  //     /*        ^         ^    */
  //     /*     uname_b   uname_e */
  //     if (!parse_credentials (uname_b, uname_e - 1, &user, &passwd))
  //       {
  //         error_code = PE_INVALID_USER_NAME;
  //         goto error;
  //       }
    //}

  u = calloc(1,sizeof(struct url));
  u->scheme = scheme;
  u->host   = strdupdelim (host_b, host_e);
  u->port   = port;

  u->path = strdupdelim (path_b, path_e);
  //path_modified = path_simplify (scheme, u->path);
  //split_path (u->path, &u->dir, &u->file);

  //host_modified = lowercase_str (u->host);

  /* Decode %HH sequences in host name.  This is important not so much
     to support %HH sequences in host names (which other browser
     don't), but to support binary characters (which will have been
     converted to %HH by reencode_escapes).  */
//  if (strchr (u->host, '%'))
//    {
//     // url_unescape (u->host);
//      //host_modified = true;

//      /* check for invalid control characters in host name */
//      for (p = u->host; *p; p++)
//        {
//          if (c_iscntrl(*p))
//            {
//              url_free(u);
//              error_code = PE_INVALID_HOST_NAME;
//              goto error;
//            }
//        }

//      /* Apply IDNA regardless of iri->utf8_encode status */
//      if (opt.enable_iri && iri)
//        {
//          char *new = idn_encode (iri, u->host);
//          if (new)
//            {
//              xfree (u->host);
//              u->host = new;
//              host_modified = true;
//            }
//        }
//    }

//  if (params_b)
//    u->params = strdupdelim (params_b, params_e);
//  if (query_b)
//    u->query = strdupdelim (query_b, query_e);
//  if (fragment_b)
//    u->fragment = strdupdelim (fragment_b, fragment_e);

//  if (opt.enable_iri || path_modified || u->fragment || host_modified || path_b == path_e)
//    {
//      /* If we suspect that a transformation has rendered what
//         url_string might return different from URL_ENCODED, rebuild
//         u->url using url_string.  */
//      u->url = url_string (u, URL_AUTH_SHOW);

//      if (url_encoded != url)
//        xfree (url_encoded);
//    }
//  else
//    {
//      if (url_encoded == url)
//        u->url = xstrdup (url);
//      else
//        u->url = (char *) url_encoded;
//    }

  return u;

// error:
//  /* Cleanup in case of error: */
//  if (url_encoded && url_encoded != url)
//    xfree (url_encoded);

  /* Transmit the error code to the caller, if the caller wants to
     know.  */
//  if (error)
//    *error = error_code;
  return NULL;
}


void
url_free (struct url *url)
{
  if (url)
    {
      free (url->host);

      free (url->path);
      free (url->url);

      free (url->params);
      free (url->query);
      free (url->fragment); 

      free (url->dir);
      free (url->file);

      free (url);
    }
}
