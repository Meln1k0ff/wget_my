#include "http.h"
#include "url.h"
#include "utils.h"
#include "options.h"
#include "wget.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>


#define HTTP_STATUS_OK                    200
#define HTTP_STATUS_CREATED               201
#define HTTP_STATUS_ACCEPTED              202
#define HTTP_STATUS_NO_CONTENT            204
#define HTTP_STATUS_PARTIAL_CONTENTS      206

/* Redirection 3xx.  */
#define HTTP_STATUS_MULTIPLE_CHOICES      300
#define HTTP_STATUS_MOVED_PERMANENTLY     301
#define HTTP_STATUS_MOVED_TEMPORARILY     302
#define HTTP_STATUS_SEE_OTHER             303 /* from HTTP/1.1 */
#define HTTP_STATUS_NOT_MODIFIED          304
#define HTTP_STATUS_TEMPORARY_REDIRECT    307 /* from HTTP/1.1 */
#define HTTP_STATUS_PERMANENT_REDIRECT    308 /* from HTTP/1.1 */

/* Client error 4xx.  */
#define HTTP_STATUS_BAD_REQUEST           400
#define HTTP_STATUS_UNAUTHORIZED          401
#define HTTP_STATUS_FORBIDDEN             403
#define HTTP_STATUS_NOT_FOUND             404
#define HTTP_STATUS_RANGE_NOT_SATISFIABLE 416

/* Server errors 5xx.  */
#define HTTP_STATUS_INTERNAL              500
#define HTTP_STATUS_NOT_IMPLEMENTED       501
#define HTTP_STATUS_BAD_GATEWAY           502
#define HTTP_STATUS_UNAVAILABLE           503
#define HTTP_STATUS_GATEWAY_TIMEOUT       504

enum rp {
  rel_none, rel_name, rel_value, rel_both
};

struct request_header {
  char *name, *value;
  enum rp release_policy;
};

struct request {
  const char *method;
  char *arg;
  struct request_header *headers;
  int hcount, hcapacity;
};

 struct request *
request_new (const char *method, char *arg)
{
  struct request *req = calloc(1,sizeof(struct request));
  req->hcapacity = 8;
  req->headers = malloc(req->hcapacity * sizeof (struct request_header));
  req->method = method;
  req->arg = arg;
  return req;
}


static void
request_set_header (struct request *req, const char *name, const char *value,
                    enum rp release_policy)
{
  struct request_header *hdr;
  int i;

  if (!value)
    {
      /* A NULL value is a no-op; if freeing the name is requested,
         free it now to avoid leaks.  */
      if (release_policy == rel_name || release_policy == rel_both)
        free (name);
      return;
    }

  for (i = 0; i < req->hcount; i++)
    {
      hdr = &req->headers[i];
      if (0 == c_strcasecmp (name, hdr->name))
        {
          /* Replace existing header. */
          release_header (hdr);
          hdr->name = (void *)name;
          hdr->value = (void *)value;
          hdr->release_policy = release_policy;
          return;
        }
    }

  /* Install new header. */

  if (req->hcount >= req->hcapacity)
    {
      req->hcapacity <<= 1;
      req->headers = realloc (req->headers, req->hcapacity * sizeof (*hdr));
    }
  hdr = &req->headers[req->hcount++];
  hdr->name = (void *)name;
  hdr->value = (void *)value;
  hdr->release_policy = release_policy;
}

static struct request *
initialize_request (const struct url *u, struct http_stat *hs, int *dt, /*struct url *proxy*/
                    bool inhibit_keep_alive, /*bool *basic_auth_finished,*/
                    int *body_data_size, /*char **user, char **passwd,*/ int *ret)
{
  //bool head_only = !!(*dt & HEAD_ONLY);
  struct request *req;

    //only GET
  /* Prepare the request to send. */
    char *meth_arg;
    const char *meth = "GET";
    //meth = opt.method;
    /* Use the full path, i.e. one that includes the leading slash and
       the query string.  E.g. if u->path is "foo/bar" and u->query is
       "param=value", full_path will be "/foo/bar?param=value".  */

    meth_arg = url_full_path (u);
    req = request_new (meth, meth_arg);


  request_set_header (req, "Referer", (char *) hs->referer, rel_none);
//  if (*dt & SEND_NOCACHE)
//    {
//      /* Cache-Control MUST be obeyed by all HTTP/1.1 caching mechanisms...  */
//      request_set_header (req, "Cache-Control", "no-cache", rel_none);

//      /* ... but some HTTP/1.0 caches doesn't implement Cache-Control.  */
//      request_set_header (req, "Pragma", "no-cache", rel_none);
//    }
//  if (*dt & IF_MODIFIED_SINCE)
//    {
//      char strtime[32];
//      uerr_t err = time_to_rfc1123 (hs->orig_file_tstamp, strtime, countof (strtime));

//      if (err != RETROK)
//        {
//          logputs (LOG_VERBOSE, _("Cannot convert timestamp to http format. "
//                                  "Falling back to time 0 as last modification "
//                                  "time.\n"));
//          strcpy (strtime, "Thu, 01 Jan 1970 00:00:00 GMT");
//        }
//      request_set_header (req, "If-Modified-Since", xstrdup (strtime), rel_value);
//    }
  if (hs->restval)
    request_set_header (req, "Range",
                        aprintf ("bytes=%s-",
                                 number_to_static_string (hs->restval)),
                        rel_value);
  SET_USER_AGENT (req);
  request_set_header (req, "Accept", "*/*", rel_none);
  request_set_header (req, "Accept-Encoding", "identity", rel_none);

  /* Find the username with priority */
  if (u->user)
    *user = u->user;
  else if (opt.user && (opt.use_askpass || opt.ask_passwd))
    *user = opt.user;
  else if (opt.http_user)
    *user = opt.http_user;
  else if (opt.user)
    *user = opt.user;
  else
    *user = NULL;

  /* Find the password with priority */
  if (u->passwd)
    *passwd = u->passwd;
  else if (opt.passwd && (opt.use_askpass || opt.ask_passwd))
    *passwd = opt.passwd;
  else if (opt.http_passwd)
    *passwd = opt.http_passwd;
  else if (opt.passwd)
    *passwd = opt.passwd;
  else
    *passwd = NULL;

  /* Check for ~/.netrc if none of the above match */
  if (opt.netrc && (!*user || !*passwd))
    search_netrc (u->host, (const char **) user, (const char **) passwd, 0, NULL);

  /* We only do "site-wide" authentication with "global" user/password
   * values unless --auth-no-challenge has been requested; URL user/password
   * info overrides. */
  if (*user && *passwd && (!u->user || opt.auth_without_challenge))
    {
      /* If this is a host for which we've already received a Basic
       * challenge, we'll go ahead and send Basic authentication creds. */
      *basic_auth_finished = maybe_send_basic_creds (u->host, *user, *passwd, req);
    }

  /* Generate the Host header, HOST:PORT.  Take into account that:

     - Broken server-side software often doesn't recognize the PORT
       argument, so we must generate "Host: www.server.com" instead of
       "Host: www.server.com:80" (and likewise for https port).

     - IPv6 addresses contain ":", so "Host: 3ffe:8100:200:2::2:1234"
       becomes ambiguous and needs to be rewritten as "Host:
       [3ffe:8100:200:2::2]:1234".  */
  {
    /* Formats arranged for hfmt[add_port][add_squares].  */
    static const char *hfmt[][2] = {
      { "%s", "[%s]" }, { "%s:%d", "[%s]:%d" }
    };
    int add_port = u->port != scheme_default_port (u->scheme);
    int add_squares = strchr (u->host, ':') != NULL;
    request_set_header (req, "Host",
                        printf (hfmt[add_port][add_squares], u->host, u->port),
                        rel_value);
  }

  if (inhibit_keep_alive)
    request_set_header (req, "Connection", "Close", rel_none);
//  else
//    {
      //request_set_header (req, "Connection", "Keep-Alive", rel_none);
//      if (proxy)
//        request_set_header (req, "Proxy-Connection", "Keep-Alive", rel_none);
//    }
  //only GET
  if (opt.method)
    {

      if (opt.body_data || opt.body_file)
        {
          request_set_header (req, "Content-Type",
                              "application/x-www-form-urlencoded", rel_none);

          if (opt.body_data)
            *body_data_size = strlen (opt.body_data);
          else
            {
              *body_data_size = file_size (opt.body_file);
              if (*body_data_size == -1)
                {
//                  printf (LOG_NOTQUIET, _("BODY data file %s missing: %s\n"),
//                             quote (opt.body_file), strerror (errno));
                  request_free (&req);
                  *ret = FILEBADFILE;
                  return NULL;
                }
            }
          request_set_header (req, "Content-Length",
                              xstrdup (number_to_static_string (*body_data_size)),
                              rel_value);
        }
      else if (strcasecmp (opt.method, "post") == 0
               || strcasecmp (opt.method, "put") == 0
               || strcasecmp (opt.method, "patch") == 0)
        request_set_header (req, "Content-Length", "0", rel_none);
    }
  return req;
}



static uerr_t
establish_connection (const struct url *u, const struct url **conn_ref,
                      struct http_stat *hs, struct request **req_ref,
                      bool inhibit_keep_alive,
                      int *sock_ref)
{
  bool host_lookup_failed = false;
  int sock = *sock_ref;
  struct request *req = *req_ref;
  const struct url *conn = *conn_ref;
  struct response *resp;
  int write_error;
  int statcode;

//  if (! inhibit_keep_alive)
//    {
//      /* Look for a persistent connection to target host, unless a
//         proxy is used.  The exception is when SSL is in use, in which
//         case the proxy is nothing but a passthrough to the target
//         host, registered as a connection to the latter.  */
//      const struct url *relevant = conn;

//      if (persistent_available_p (relevant->host, relevant->port,
//#ifdef HAVE_SSL
//                                  relevant->scheme == SCHEME_HTTPS,
//#else
//                                  0,
//#endif
//                                  &host_lookup_failed))
//        {
//          int family = socket_family (pconn.socket, ENDPOINT_PEER);
//          sock = pconn.socket;
//          *using_ssl = pconn.ssl;
//#if ENABLE_IPV6
//          if (family == AF_INET6)
//             logprintf (LOG_VERBOSE, _("Reusing existing connection to [%s]:%d.\n"),
//                        quotearg_style (escape_quoting_style, pconn.host),
//                         pconn.port);
//          else
//#endif
//             logprintf (LOG_VERBOSE, _("Reusing existing connection to %s:%d.\n"),
//                        quotearg_style (escape_quoting_style, pconn.host),
//                        pconn.port);
//          DEBUGP (("Reusing fd %d.\n", sock));
//          if (pconn.authorized)
//            /* If the connection is already authorized, the "Basic"
//               authorization added by code above is unnecessary and
//               only hurts us.  */
//            request_remove_header (req, "Authorization");
//        }
//      else if (host_lookup_failed)
//        {
//          logprintf(LOG_NOTQUIET,
//                    _("%s: unable to resolve host address %s\n"),
//                    exec_name, quote (relevant->host));
//          return HOSTERR;
//        }
//      else if (sock != -1)
//        {
//          sock = -1;
//        }
//    }

  if (sock < 0)
    {
      sock = connect_to_host (conn->host, conn->port);
      if (sock == E_HOST)
        return HOSTERR;
      else if (sock < 0)
        return (retryable_socket_connect_error (errno)
                ? CONERROR : CONIMPOSSIBLE);

    }
  *conn_ref = conn;
  *req_ref = req;
  *sock_ref = sock;
  return RETROK;
}

static int
gethttp (const struct url *u, struct url *original_url, struct http_stat *hs,
         int *dt, struct iri *iri, int count)
{
  struct request *req = NULL;

  char *type = NULL;
  char *proxyauth;
  int statcode;
  int write_error;
  int contlen, contrange;
  const struct url *conn;
  FILE *fp;
  int err;
  int retval;

  int sock = -1;

  /* Set to 1 when the authorization has already been sent and should
     not be tried again. */
//  bool auth_finished = false;

  /* Set to 1 when just globally-set Basic authorization has been sent;
   * should prevent further Basic negotiations, but not other
   * mechanisms. */
//  bool basic_auth_finished = false;

  /* Whether NTLM authentication is used for this request. */
//  bool ntlm_seen = false;

  /* Whether our connection to the remote host is through SSL.  */
//  bool using_ssl = false;

  /* Whether a HEAD request will be issued (as opposed to GET or
     POST). */
//  bool head_only = !!(*dt & HEAD_ONLY);

  /* Whether conditional get request will be issued.  */
//  bool cond_get = !!(*dt & IF_MODIFIED_SINCE);

  char *head = NULL;
  struct response *resp = NULL;
  char hdrval[512];
  char *message = NULL;

  /* Declare WARC variables. */
//  bool warc_enabled = (opt.warc_filename != NULL);
//  FILE *warc_tmp = NULL;
//  char warc_timestamp_str [21];
//  char warc_request_uuid [48];
//  ip_address *warc_ip = NULL;
//  off_t warc_payload_offset = -1;

  /* Whether this connection will be kept alive after the HTTP request
     is done. */
//  bool keep_alive; dont keep alive

  /* Is the server using the chunked transfer encoding?  */
  bool chunked_transfer_encoding = false;

  /* Whether keep-alive should be inhibited.  */
  bool inhibit_keep_alive =
    !opt.http_keep_alive || opt.ignore_length;

  /* Headers sent when using POST. */
  int body_data_size = 0;


  /* Initialize certain elements of struct http_stat.  */
  hs->len = 0;
  hs->contlen = -1;
  hs->res = -1;
  hs->rderrmsg = NULL;
  hs->newloc = NULL;
  free (hs->remote_time);
  hs->error = NULL;
  hs->message = NULL;
//  hs->local_encoding = ENC_NONE;
//  hs->remote_encoding = ENC_NONE;

  conn = u;

  {
    uerr_t ret;
    //no keep-alive
    req = initialize_request (u, hs, dt, inhibit_keep_alive,
                              &basic_auth_finished, &body_data_size,
                              /*&user, &passwd,*/ &ret);
    if (req == NULL)
      {
        retval = ret;
//        goto cleanup;
      }
  }
// retry_with_auth:
  /* We need to come back here when the initial attempt to retrieve
     without authorization header fails.  (Expected to happen at least
     for the Digest authorization scheme.)  */

//  if (opt.cookies)
//    request_set_header (req, "Cookie",
//                        cookie_header (wget_cookie_jar,
//                                       u->host, u->port, u->path,
//                                       0
//                                       ),
//                        rel_value);

  /* Add the user headers. */
//  if (opt.user_headers)
//    {
//      int i;
//      for (i = 0; opt.user_headers[i]; i++)
//        request_set_user_header (req, opt.user_headers[i]);
//    }

//  proxyauth = NULL;
//  if (proxy)
//    {
//      conn = proxy;
//      initialize_proxy_configuration (u, req, proxy, &proxyauth);
//    }
//  keep_alive = true;

  /* Establish the connection.  */
//  if (inhibit_keep_alive)
//    keep_alive = false;

  {
    uerr_t conn_err = establish_connection (u, &conn, hs, &req,
                                            &sock);
    if (conn_err != RETROK)
      {
        retval = conn_err;
//        goto cleanup;
      }
  }

  /* Open the temporary file where we will write the request. */
  if (warc_enabled)
    {
      warc_tmp = warc_tempfile ();
      if (warc_tmp == NULL)
        {
          CLOSE_INVALIDATE (sock);
          retval = WARC_TMP_FOPENERR;
//          goto cleanup;
        }

      if (! proxy)
        {
          warc_ip = (ip_address *) alloca (sizeof (ip_address));
          socket_ip_address (sock, warc_ip, ENDPOINT_PEER);
        }
    }

  /* Send the request to server.  */
  write_error = request_send (req, sock, warc_tmp);

  if (write_error >= 0)
    {
      if (opt.body_data)
        {
          DEBUGP (("[BODY data: %s]\n", opt.body_data));
          write_error = fd_write (sock, opt.body_data, body_data_size, -1);
          if (write_error >= 0 && warc_tmp != NULL)
            {
              int warc_tmp_written;

              /* Remember end of headers / start of payload. */
              warc_payload_offset = ftello (warc_tmp);

              /* Write a copy of the data to the WARC record. */
              warc_tmp_written = fwrite (opt.body_data, 1, body_data_size, warc_tmp);
              if (warc_tmp_written != body_data_size)
                write_error = -2;
            }
         }
      else if (opt.body_file && body_data_size != 0)
        {
          if (warc_tmp != NULL)
            /* Remember end of headers / start of payload */
            warc_payload_offset = ftello (warc_tmp);

          write_error = body_file_send (sock, opt.body_file, body_data_size, warc_tmp);
        }
    }

  if (write_error < 0)
    {
      CLOSE_INVALIDATE (sock);

      if (warc_tmp != NULL)
        fclose (warc_tmp);

      if (write_error == -2)
        retval = WARC_TMP_FWRITEERR;
      else
        retval = WRITEFAILED;
//      goto cleanup;
    }
  logprintf (LOG_VERBOSE, _("%s request sent, awaiting response... "),
             proxy ? "Proxy" : "HTTP");
  contlen = -1;
  contrange = 0;
  *dt &= ~RETROKF;


//  if (warc_enabled)
//    {
//      bool warc_result;

//      /* Generate a timestamp and uuid for this request. */
//      warc_timestamp (warc_timestamp_str, sizeof (warc_timestamp_str));
//      warc_uuid_str (warc_request_uuid);

//      /* Create a request record and store it in the WARC file. */
//      warc_result = warc_write_request_record (u->url, warc_timestamp_str,
//                                               warc_request_uuid, warc_ip,
//                                               warc_tmp, warc_payload_offset);
//      if (! warc_result)
//        {
//          CLOSE_INVALIDATE (sock);
//          retval = WARC_ERR;
////          goto cleanup;
//        }

//      /* warc_write_request_record has also closed warc_tmp. */
//    }

  /* Repeat while we receive a 10x response code.  */
  {
    bool _repeat;

    do
      {
        head = read_http_response_head (sock);
        if (!head)
          {
            if (errno == 0)
              {
                logputs (LOG_NOTQUIET, _("No data received.\n"));
                CLOSE_INVALIDATE (sock);
                retval = HEOF;
              }
            else
              {
                logprintf (LOG_NOTQUIET, _("Read error (%s) in headers.\n"),
                           fd_errstr (sock));
                CLOSE_INVALIDATE (sock);
                retval = HERR;
              }
//            goto cleanup;
          }
        DEBUGP (("\n---response begin---\n%s---response end---\n", head));

        resp = resp_new (head);

        /* Check for status line.  */
        free (message);
        statcode = resp_status (resp, &message);
        if (statcode < 0)
          {
            char *tms = datetime_str (time (NULL));
            logprintf (LOG_VERBOSE, "%d\n", statcode);
            logprintf (LOG_NOTQUIET, _("%s ERROR %d: %s.\n"), tms, statcode,
                       quotearg_style (escape_quoting_style,
                                       _("Malformed status line")));
            CLOSE_INVALIDATE (sock);
            retval = HERR;
//            goto cleanup;
          }

        if (H_10X (statcode))
          {
            free (head);
            resp_free (&resp);
            _repeat = true;
            DEBUGP (("Ignoring response\n"));
          }
        else
          {
            _repeat = false;
          }
      }
    while (_repeat);
  }

  free (hs->message);
  hs->message = xstrdup (message);
  if (!opt.server_response)
    printf ("%2d %s\n", statcode);
  else
    {
      //logprintf (LOG_VERBOSE, "\n");
//      print_server_response (resp, "  ");
    }

  if (!opt.ignore_length
      && resp_header_copy (resp, "Content-Length", hdrval, sizeof (hdrval)))
    {
      int parsed;
      errno = 0;
      parsed = str_to_wgint (hdrval, NULL, 10);
      if (parsed == INT_MAX && errno == ERANGE)
        {
          /* Out of range.
             #### If Content-Length is out of range, it most likely
             means that the file is larger than 2G and that we're
             compiled without LFS.  In that case we should probably
             refuse to even attempt to download the file.  */
          contlen = -1;
        }
      else if (parsed < 0)
        {
          /* Negative Content-Length; nonsensical, so we can't
             assume any information about the content to receive. */
          contlen = -1;
        }
      else
        contlen = parsed;
    }

  /* Check for keep-alive related responses. */
  /*if (!inhibit_keep_alive)
    {
      if (resp_header_copy (resp, "Connection", hdrval, sizeof (hdrval)))
        {
          if (0 == c_strcasecmp (hdrval, "Close"))
            keep_alive = false;
        }
    }*/

  chunked_transfer_encoding = false;
  if (resp_header_copy (resp, "Transfer-Encoding", hdrval, sizeof (hdrval))
      && 0 == strcasecmp (hdrval, "chunked"))
    chunked_transfer_encoding = true;

  /* Handle (possibly multiple instances of) the Set-Cookie header. */
//  if (opt.cookies)
//    {
//      int scpos;
//      const char *scbeg, *scend;
//      /* The jar should have been created by now. */
//      assert (wget_cookie_jar != NULL);
//      for (scpos = 0;
//           (scpos = resp_header_locate (resp, "Set-Cookie", scpos,
//                                        &scbeg, &scend)) != -1;
//           ++scpos)
//        {
//          char *set_cookie; BOUNDED_TO_ALLOCA (scbeg, scend, set_cookie);
//          cookie_handle_set_cookie (wget_cookie_jar, u->host, u->port,
//                                    u->path, set_cookie);
//        }
//    }

//  if (keep_alive)
//  {
//  }
    /* The server has promised that it will not close the connection
       when we're done.  This means that we can register it.  */
    //register_persistent (conn->host, conn->port, sock, using_ssl);

  if (statcode == HTTP_STATUS_UNAUTHORIZED)
    {
      /* Authorization is required.  */
      uerr_t auth_err = RETROK;
      bool retry;
      /* Normally we are not interested in the response body.
         But if we are writing a WARC file we are: we like to keep everything.  */
//      if (warc_enabled)
//        {
//          int _err;
//          type = resp_header_strdup (resp, "Content-Type");
//          _err = read_response_body (hs, sock, NULL, contlen, 0,
//                                    chunked_transfer_encoding,
//                                    u->url, warc_timestamp_str,
//                                    warc_request_uuid, warc_ip, type,
//                                    statcode, head);
//          free (type);

//          if (_err != RETRFINISHED || hs->res < 0)
//            {
//              CLOSE_INVALIDATE (sock);
//              retval = _err;
//              goto cleanup;
//            }
//          else
//            CLOSE_FINISH (sock);
//        }
//      else
//        {
//          /* Since WARC is disabled, we are not interested in the response body.  */
//          if (keep_alive && !head_only
//              && skip_short_body (sock, contlen, chunked_transfer_encoding))
//            CLOSE_FINISH (sock);
//          else
//            CLOSE_INVALIDATE (sock);
//        }

//      pconn.authorized = false;

//      {
//        auth_err = check_auth (u, user, passwd, resp, req,
//                               &ntlm_seen, &retry,
//                               &basic_auth_finished,
//                               &auth_finished);
//        if (auth_err == RETROK && retry)
//          {
//            free (hs->message);
//            resp_free (&resp);
//            free (message);
//            free (head);
//            goto retry_with_auth;
//          }
//      }
      if (auth_err == RETROK)
        retval = AUTHFAILED;
      else
        retval = auth_err;
//      goto cleanup;
    }
//  else /* statcode != HTTP_STATUS_UNAUTHORIZED */
//    {
//      /* Kludge: if NTLM is used, mark the TCP connection as authorized. */
//      if (ntlm_seen)
//        pconn.authorized = true;
//    }

//  {
//    uerr_t ret = check_file_output (u, hs, resp, hdrval, sizeof hdrval);
//    if (ret != RETROK)
//      {
//        retval = ret;
//        goto cleanup;
//      }
//  }

  hs->statcode = statcode;
  if (statcode == -1)
    hs->error = strdup (_("Malformed status line"));
  else if (!*message)
    hs->error = strdup (_("(no description)"));
  else
    hs->error = strdup (message);

  type = resp_header_strdup (resp, "Content-Type");
  if (type)
    {
      char *tmp = strchr (type, ';');
      if (tmp)
        {
//#ifdef ENABLE_IRI
//          /* sXXXav: only needed if IRI support is enabled */
//          char *tmp2 = tmp + 1;
//#endif

          while (tmp > type && c_isspace (tmp[-1]))
            --tmp;
          *tmp = '\0';

//#ifdef ENABLE_IRI
//          /* Try to get remote encoding if needed */
//          if (opt.enable_iri && !opt.encoding_remote)
//            {
//              tmp = parse_charset (tmp2);
//              if (tmp)
//                set_content_encoding (iri, tmp);
//              free (tmp);
//            }
//#endif
        }
    }
  hs->newloc = resp_header_strdup (resp, "Location");
  hs->remote_time = resp_header_strdup (resp, "Last-Modified");
  if (!hs->remote_time) // now look for the Wayback Machine's timestamp
    hs->remote_time = resp_header_strdup (resp, "X-Archive-Orig-last-modified");

  if (resp_header_copy (resp, "Content-Range", hdrval, sizeof (hdrval)))
    {
      int first_byte_pos, last_byte_pos, entity_length;
      if (parse_content_range (hdrval, &first_byte_pos, &last_byte_pos,
                               &entity_length))
        {
          contrange = first_byte_pos;
          contlen = last_byte_pos - first_byte_pos + 1;
        }
    }

  if (resp_header_copy (resp, "Content-Encoding", hdrval, sizeof (hdrval)))
    {
//      hs->local_encoding = ENC_INVALID;

//      switch (hdrval[0])
//        {
//        case 'b': case 'B':
//          if (0 == c_strcasecmp(hdrval, "br"))
//            hs->local_encoding = ENC_BROTLI;
//          break;
//        case 'c': case 'C':
//          if (0 == c_strcasecmp(hdrval, "compress"))
//            hs->local_encoding = ENC_COMPRESS;
//          break;
//        case 'd': case 'D':
//          if (0 == c_strcasecmp(hdrval, "deflate"))
//            hs->local_encoding = ENC_DEFLATE;
//          break;
//        case 'g': case 'G':
//          if (0 == c_strcasecmp(hdrval, "gzip"))
//            hs->local_encoding = ENC_GZIP;
//          break;
//        case 'i': case 'I':
//          if (0 == c_strcasecmp(hdrval, "identity"))
//            hs->local_encoding = ENC_NONE;
//          break;
//        case 'x': case 'X':
//          if (0 == c_strcasecmp(hdrval, "x-compress"))
//            hs->local_encoding = ENC_COMPRESS;
//          else if (0 == c_strcasecmp(hdrval, "x-gzip"))
//            hs->local_encoding = ENC_GZIP;
//          break;
//        case '\0':
//          hs->local_encoding = ENC_NONE;
//        }

//      if (hs->local_encoding == ENC_INVALID)
//        {
//          DEBUGP (("Unrecognized Content-Encoding: %s\n", hdrval));
//          hs->local_encoding = ENC_NONE;
//        }

    }

  /* 20x responses are counted among successful by default.  */
  if (H_20X (statcode))
    *dt |= RETROKF;

  if (statcode == HTTP_STATUS_NO_CONTENT)
    {
      /* 204 response has no body (RFC 2616, 4.3) */

      /* In case the caller cares to look...  */
      hs->len = 0;
      hs->res = 0;
      hs->restval = 0;

      CLOSE_FINISH (sock);

      retval = RETRFINISHED;
//      goto cleanup;
    }
}

  /* Return if redirected.  */
//  if (H_REDIRECTED (statcode) || statcode == HTTP_STATUS_MULTIPLE_CHOICES)
//    {
//      /* RFC2068 says that in case of the 300 (multiple choices)
//         response, the server can output a preferred URL through
//         `Location' header; otherwise, the request should be treated
//         like GET.  So, if the location is set, it will be a
//         redirection; otherwise, just proceed normally.  */
//      if (statcode == HTTP_STATUS_MULTIPLE_CHOICES && !hs->newloc)
//        *dt |= RETROKF;
//      else
//        {
//          logprintf (LOG_VERBOSE,
//                     _("Location: %s%s\n"),
//                     hs->newloc ? escnonprint_uri (hs->newloc) : _("unspecified"),
//                     hs->newloc ? _(" [following]") : "");

//          /* In case the caller cares to look...  */
//          hs->len = 0;
//          hs->res = 0;
//          hs->restval = 0;

//          /* Normally we are not interested in the response body of a redirect.
//             But if we are writing a WARC file we are: we like to keep everything.  */
//          if (warc_enabled)
//            {
//              int _err = read_response_body (hs, sock, NULL, contlen, 0,
//                                            chunked_transfer_encoding,
//                                            u->url, warc_timestamp_str,
//                                            warc_request_uuid, warc_ip, type,
//                                            statcode, head);

//              if (_err != RETRFINISHED || hs->res < 0)
//                {
//                  CLOSE_INVALIDATE (sock);
//                  retval = _err;
//                  goto cleanup;
//                }
//              else
//                CLOSE_FINISH (sock);
//            }
//          else
//            {
//              /* Since WARC is disabled, we are not interested in the response body.  */
//              if (keep_alive && !head_only
//                  && skip_short_body (sock, contlen, chunked_transfer_encoding))
//                CLOSE_FINISH (sock);
//              else
//                CLOSE_INVALIDATE (sock);
//            }

//          /* From RFC2616: The status codes 303 and 307 have
//             been added for servers that wish to make unambiguously
//             clear which kind of reaction is expected of the client.

//             A 307 should be redirected using the same method,
//             in other words, a POST should be preserved and not
//             converted to a GET in that case.

//             With strict adherence to RFC2616, POST requests are not
//             converted to a GET request on 301 Permanent Redirect
//             or 302 Temporary Redirect.

//             A switch may be provided later based on the HTTPbis draft
//             that allows clients to convert POST requests to GET
//             requests on 301 and 302 response codes. */
//          switch (statcode)
//            {
//            case HTTP_STATUS_TEMPORARY_REDIRECT:
//            case HTTP_STATUS_PERMANENT_REDIRECT:
//              retval = NEWLOCATION_KEEP_POST;
//              goto cleanup;
//            case HTTP_STATUS_MOVED_PERMANENTLY:
//              if (opt.method && c_strcasecmp (opt.method, "post") != 0)
//                {
//                  retval = NEWLOCATION_KEEP_POST;
//                  goto cleanup;
//                }
//              break;
//            case HTTP_STATUS_MOVED_TEMPORARILY:
//              if (opt.method && c_strcasecmp (opt.method, "post") != 0)
//                {
//                  retval = NEWLOCATION_KEEP_POST;
//                  goto cleanup;
//                }
//              break;
//            }
//          retval = NEWLOCATION;
//          goto cleanup;
//        }
//    }

//  if (cond_get)
//    {
//      if (statcode == HTTP_STATUS_NOT_MODIFIED)
//        {
////          logprintf (LOG_VERBOSE,
////                     _ ("File %s not modified on server. Omitting download.\n\n"),
////                     quote (hs->local_file));
////          *dt |= RETROKF;
//          CLOSE_FINISH (sock);
//          retval = RETRUNNEEDED;
//        }
//    }

//  set_content_type (dt, type);

//  if (opt.adjust_extension)
//    {
//      const char *encoding_ext = NULL;
//      switch (hs->local_encoding)
//        {
//        case ENC_INVALID:
//        case ENC_NONE:
//          break;
//        case ENC_BROTLI:
//          encoding_ext = ".br";
//          break;
//        case ENC_COMPRESS:
//          encoding_ext = ".Z";
//          break;
//        case ENC_DEFLATE:
//          encoding_ext = ".zlib";
//          break;
//        case ENC_GZIP:
//          encoding_ext = ".gz";
//          break;
//        default:
//          DEBUGP (("No extension found for encoding %d\n",
//                   hs->local_encoding));
//      }
//      if (encoding_ext != NULL)
//        {
//          char *file_ext = strrchr (hs->local_file, '.');
//          /* strip Content-Encoding extension (it will be re-added later) */
//          if (file_ext != NULL && 0 == strcasecmp (file_ext, encoding_ext))
//            *file_ext = '\0';
//        }
//      if (*dt & TEXTHTML)
//        /* -E / --adjust-extension / adjust_extension = on was specified,
//           and this is a text/html file.  If some case-insensitive
//           variation on ".htm[l]" isn't already the file's suffix,
//           tack on ".html". */
//        {
//          ensure_extension (hs, ".html", dt);
//        }
//      else if (*dt & TEXTCSS)
//        {
//          ensure_extension (hs, ".css", dt);
//        }
//      if (encoding_ext != NULL)
//        {
//          ensure_extension (hs, encoding_ext, dt);
//        }
//    }

//  if (cond_get)
//    {
//      /* Handle the case when server ignores If-Modified-Since header.  */
//      if (statcode == HTTP_STATUS_OK && hs->remote_time)
//        {
//          time_t tmr = http_atotm (hs->remote_time);

//          /* Check if the local file is up-to-date based on Last-Modified header
//             and content length.  */
//          if (tmr != (time_t) - 1 && tmr <= hs->orig_file_tstamp
//              && (contlen == -1 || contlen == hs->orig_file_size))
//            {
//              logprintf (LOG_VERBOSE,
//                         _("Server ignored If-Modified-Since header for file %s.\n"
//                           "You might want to add --no-if-modified-since option."
//                           "\n\n"),
//                         quote (hs->local_file));
//              *dt |= RETROKF;
//              CLOSE_INVALIDATE (sock);
//              retval = RETRUNNEEDED;
//              goto cleanup;
//            }
//        }
//    }

//  if (statcode == HTTP_STATUS_RANGE_NOT_SATISFIABLE
//      || (!opt.timestamping && hs->restval > 0 && statcode == HTTP_STATUS_OK
//          && contrange == 0 && contlen >= 0 && hs->restval >= contlen))
//    {
//      /* If `-c' is in use and the file has been fully downloaded (or
//         the remote file has shrunk), Wget effectively requests bytes
//         after the end of file and the server response with 416
//         (or 200 with a <= Content-Length.  */
//      logputs (LOG_VERBOSE, _("\
//\n    The file is already fully retrieved; nothing to do.\n\n"));
//      /* In case the caller inspects. */
//      hs->len = contlen;
//      hs->res = 0;
//      /* Mark as successfully retrieved. */
//      *dt |= RETROKF;

//      /* Try to maintain the keep-alive connection. It is often cheaper to
//       * consume some bytes which have already been sent than to negotiate
//       * a new connection. However, if the body is too large, or we don't
//       * care about keep-alive, then simply terminate the connection */
//      if (keep_alive &&
//          skip_short_body (sock, contlen, chunked_transfer_encoding))
//        CLOSE_FINISH (sock);
//      else
//        CLOSE_INVALIDATE (sock);
//      retval = RETRUNNEEDED;
//      goto cleanup;
//    }

//  if ((contrange != 0 && contrange != hs->restval)
//      || (H_PARTIAL (statcode) && !contrange && hs->restval))
//    {
//      /* The Range request was somehow misunderstood by the server.
//         Bail out.  */
//      CLOSE_INVALIDATE (sock);
//      retval = RANGEERR;
//      goto cleanup;
//    }
//  if (contlen == -1)
//    hs->contlen = -1;
//  else
//    hs->contlen = contlen + contrange;

//  if (opt.verbose)
//    {
//      if (*dt & RETROKF)
//        {
//          /* No need to print this output if the body won't be
//             downloaded at all, or if the original server response is
//             printed.  */
//          logputs (LOG_VERBOSE, _("Length: "));
//          if (contlen != -1)
//            {
//              logputs (LOG_VERBOSE, number_to_static_string (contlen + contrange));
//              if (contlen + contrange >= 1024)
//                logprintf (LOG_VERBOSE, " (%s)",
//                           human_readable (contlen + contrange, 10, 1));
//              if (contrange)
//                {
//                  if (contlen >= 1024)
//                    logprintf (LOG_VERBOSE, _(", %s (%s) remaining"),
//                               number_to_static_string (contlen),
//                               human_readable (contlen, 10, 1));
//                  else
//                    logprintf (LOG_VERBOSE, _(", %s remaining"),
//                               number_to_static_string (contlen));
//                }
//            }
//          else
//            logputs (LOG_VERBOSE,
//                     opt.ignore_length ? _("ignored") : _("unspecified"));
//          if (type)
//            logprintf (LOG_VERBOSE, " [%s]\n", quotearg_style (escape_quoting_style, type));
//          else
//            logputs (LOG_VERBOSE, "\n");
//        }
//    }

  /* Return if we have no intention of further downloading.  */
//  if ((!(*dt & RETROKF) && !opt.content_on_error) || head_only || (opt.spider && !opt.recursive))
//    {
//      /* In case the caller cares to look...  */
//      hs->len = 0;
//      hs->res = 0;
//      hs->restval = 0;

//      /* Normally we are not interested in the response body of a error responses.
//         But if we are writing a WARC file we are: we like to keep everything.  */
//      if (warc_enabled)
//        {
//          int _err = read_response_body (hs, sock, NULL, contlen, 0,
//                                        chunked_transfer_encoding,
//                                        u->url, warc_timestamp_str,
//                                        warc_request_uuid, warc_ip, type,
//                                        statcode, head);

//          if (_err != RETRFINISHED || hs->res < 0)
//            {
//              CLOSE_INVALIDATE (sock);
//              retval = _err;
//              goto cleanup;
//            }

//          CLOSE_FINISH (sock);
//        }
//      else
//        {
//          /* Since WARC is disabled, we are not interested in the response body.  */
//          if (head_only)
//            /* Pre-1.10 Wget used CLOSE_INVALIDATE here.  Now we trust the
//               servers not to send body in response to a HEAD request, and
//               those that do will likely be caught by test_socket_open.
//               If not, they can be worked around using
//               `--no-http-keep-alive'.  */
//            CLOSE_FINISH (sock);
//          else if (opt.spider && !opt.recursive)
//            /* we just want to see if the page exists - no downloading required */
//            CLOSE_INVALIDATE (sock);
//          else if (keep_alive
//                   && skip_short_body (sock, contlen, chunked_transfer_encoding))
//            /* Successfully skipped the body; also keep using the socket. */
//            CLOSE_FINISH (sock);
//          else
//            CLOSE_INVALIDATE (sock);
//        }

//      if (statcode == HTTP_STATUS_GATEWAY_TIMEOUT)
//        retval = GATEWAYTIMEOUT;
//      else
//        retval = RETRFINISHED;

//      goto cleanup;
//    }

//  err = open_output_stream (hs, count, &fp);
//  if (err != RETROK)
//    {
//      CLOSE_INVALIDATE (sock);
//      retval = err;
//      goto cleanup;
//    }

//#ifdef ENABLE_XATTR
//  if (opt.enable_xattr)
//    {
//      if (original_url != u)
//        set_file_metadata (u->url, original_url->url, fp);
//      else
//        set_file_metadata (u->url, NULL, fp);
//    }
//#endif

//  err = read_response_body (hs, sock, fp, contlen, contrange,
//                            chunked_transfer_encoding,
//                            u->url, warc_timestamp_str,
//                            warc_request_uuid, warc_ip, type,
//                            statcode, head);

//  if (hs->res >= 0)
//    CLOSE_FINISH (sock);
//  else
//    CLOSE_INVALIDATE (sock);

//  if (!output_stream)
//    fclose (fp);

//  retval = err;

//  cleanup:
//  free (head);
//  free (type);
//  free (message);
//  resp_free (&resp);
//  request_free (&req);

//  return retval;
//}

static int
read_response_body (struct http_stat *hs, int sock, FILE *fp, int contlen,
                    int contrange, bool chunked_transfer_encoding,
                    char *url, char *warc_timestamp_str, char *warc_request_uuid,
                    ip_address *warc_ip, char *type, int statcode, char *head)
{
  int warc_payload_offset = 0;
  FILE *warc_tmp = NULL;
  int warcerr = 0;
  int flags = 0;

  if (opt.warc_filename != NULL)
    {
      /* Open a temporary file where we can write the response before we
         add it to the WARC record.  */
      warc_tmp = warc_tempfile ();
      if (warc_tmp == NULL)
        warcerr = WARC_TMP_FOPENERR;

      if (warcerr == 0)
        {
          /* We should keep the response headers for the WARC record.  */
          int head_len = strlen (head);
          int warc_tmp_written = fwrite (head, 1, head_len, warc_tmp);
          if (warc_tmp_written != head_len)
            warcerr = WARC_TMP_FWRITEERR;
          warc_payload_offset = head_len;
        }

      if (warcerr != 0)
        {
          if (warc_tmp != NULL)
            fclose (warc_tmp);
          return warcerr;
        }
    }

  if (fp != NULL)
    {
      /* This confuses the timestamping code that checks for file size.
         #### The timestamping code should be smarter about file size.  */
      if (opt.save_headers && hs->restval == 0)
        fwrite (head, 1, strlen (head), fp);
    }

  /* Read the response body.  */
  if (contlen != -1)
    /* If content-length is present, read that much; otherwise, read
       until EOF.  The HTTP spec doesn't require the server to
       actually close the connection when it's done sending data. */
    flags |= rb_read_exactly;
  if (fp != NULL && hs->restval > 0 && contrange == 0)
    /* If the server ignored our range request, instruct fd_read_body
       to skip the first RESTVAL bytes of body.  */
    flags |= rb_skip_startpos;
  if (chunked_transfer_encoding)
    flags |= rb_chunked_transfer_encoding;

  if (hs->remote_encoding == ENC_GZIP)
    flags |= rb_compressed_gzip;

  hs->len = hs->restval;
  hs->rd_size = 0;
  /* Download the response body and write it to fp.
     If we are working on a WARC file, we simultaneously write the
     response body to warc_tmp.  */
  hs->res = fd_read_body (hs->local_file, sock, fp, contlen != -1 ? contlen : 0,
                          hs->restval, &hs->rd_size, &hs->len, &hs->dltime,
                          flags, warc_tmp);
  if (hs->res >= 0)
    {
      if (warc_tmp != NULL)
        {
          /* Create a response record and write it to the WARC file.
             Note: per the WARC standard, the request and response should share
             the same date header.  We re-use the timestamp of the request.
             The response record should also refer to the uuid of the request.  */
          bool r = warc_write_response_record (url, warc_timestamp_str,
                                               warc_request_uuid, warc_ip,
                                               warc_tmp, warc_payload_offset,
                                               type, statcode, hs->newloc);

          /* warc_write_response_record has closed warc_tmp. */

          if (! r)
            return WARC_ERR;
        }

      return RETRFINISHED;
    }

  if (warc_tmp != NULL)
    fclose (warc_tmp);

  if (hs->res == -2)
    {
      /* Error while writing to fd. */
      return FWRITEERR;
    }
  else if (hs->res == -3)
    {
      /* Error while writing to warc_tmp. */
      return WARC_TMP_FWRITEERR;
    }
  else
    {
      /* A read error! */
      hs->rderrmsg = xstrdup (fd_errstr (sock));
      return RETRFINISHED;
    }
}

/* Check whether the supplied HTTP status code is among those
   listed for the --retry-on-http-error option. */
static bool
check_retry_on_http_error (const int statcode)
{
  const char *tok = opt.retry_on_http_error;
  while (tok && *tok)
    {
      if (atoi (tok) == statcode)
        return true;
      if ((tok = strchr (tok, ',')))
        ++tok;
    }
  return false;
}

int
http_loop (const struct url *u, struct url *original_url, char **newloc,
           char **local_file, const char *referer, int *dt, /*struct url *proxy*/
           struct iri *iri)
{
  int count;
  bool got_head = false;         /* used for time-stamping and filename detection */
  bool time_came_from_head = false;
  bool got_name = false;
  char *tms;
  const char *tmrate;
  int err, ret = 0;
  time_t tmr = -1;               /* remote time-stamp */
  struct http_stat hstat;        /* HTTP status */
  struct stat st;
  bool send_head_first = true;
  bool force_full_retrieve = false;


  /* If we are writing to a WARC file: always retrieve the whole file. */
//  if (opt.warc_filename != NULL)
//    force_full_retrieve = true;


  /* Assert that no value for *LOCAL_FILE was passed. */
 // assert (local_file == NULL || *local_file == NULL);

  /* Set LOCAL_FILE parameter. */
  if (local_file && opt.output_document)
    *local_file = HYPHENP (opt.output_document) ? NULL : strdup (opt.output_document);

  /* Reset NEWLOC parameter. */
  *newloc = NULL;

  /* Warn on (likely bogus) wildcard usage in HTTP. */
//  if (opt.ftp_glob && has_wildcards_p (u->path))
//    logputs (LOG_VERBOSE, _("Warning: wildcards not supported in HTTP.\n"));

  /* Setup hstat struct. */
  //xzero (hstat);
  memset(&hstat,'\0', sizeof(struct http_stat));

  hstat.referer = referer;

  if (opt.output_document)
    {
      hstat.local_file = xstrdup (opt.output_document);
      got_name = true;
    }
//  else if (!opt.content_disposition)
//    {
//      hstat.local_file =
//        url_file_name (opt.trustservernames ? u : original_url, NULL);
//      got_name = true;
//    }

//  if (got_name && file_exists_p (hstat.local_file, NULL) && opt.noclobber && !opt.output_document)
//    {
//      /* If opt.noclobber is turned on and file already exists, do not
//         retrieve the file. But if the output_document was given, then this
//         test was already done and the file didn't exist. Hence the !opt.output_document */
//      get_file_flags (hstat.local_file, dt);
//      ret = RETROK;
//      goto exit;
//    }

  /* Reset the counter. */
  count = 0;

  /* Reset the document type. */
  *dt = 0;

  /* Skip preliminary HEAD request if we're not in spider mode.  */
//  if (!opt.spider)
//    send_head_first = false;

  /* Send preliminary HEAD request if --content-disposition and -c are used
     together.  */
//  if (opt.content_disposition && opt.always_rest)
//    send_head_first = true;

//#ifdef HAVE_METALINK
//  if (opt.metalink_over_http)
//    {
//      *dt |= METALINK_METADATA;
//      send_head_first = true;
//    }
//#endif

//  if (opt.timestamping)
//    {
//      /* Use conditional get request if requested
//       * and if timestamp is known at this moment.  */
//      if (opt.if_modified_since && !send_head_first && got_name && file_exists_p (hstat.local_file, NULL))
//        {
//          *dt |= IF_MODIFIED_SINCE;
//          {
//            uerr_t timestamp_err = set_file_timestamp (&hstat);
//            if (timestamp_err != RETROK)
//              return timestamp_err;
//          }
//        }
//        /* Send preliminary HEAD request if -N is given and we have existing
//         * destination file or content disposition is enabled.  */
//      else if (opt.content_disposition || file_exists_p (hstat.local_file, NULL))
//        send_head_first = true;
//    }

  /* THE loop */
  do
    {
      /* Increment the pass counter.  */
      ++count;
      //sleep_between_retrievals (count);

      /* Get the current time string.  */
      tms = datetime_str (time (NULL));

//      if (opt.spider && !got_head)
//        logprintf (LOG_VERBOSE,
//              _("Spider mode enabled. Check if remote file exists.\n"));

      /* Print fetch message, if opt.verbose.  */
//      if (opt.verbose)
//        {
//          char *hurl = url_string (u, URL_AUTH_HIDE_PASSWD);

//          if (count > 1)
//            {
//              char tmp[256];
//              sprintf (tmp, _("(try:%2d)"), count);
//              logprintf (LOG_NOTQUIET, "--%s--  %s  %s\n",
//                         tms, tmp, hurl);
//            }
//          else
//            {
//              logprintf (LOG_NOTQUIET, "--%s--  %s\n",
//                         tms, hurl);
//            }

//#ifdef WINDOWS
//          ws_changetitle (hurl);
//#endif
//          free (hurl);
//        }

      /* Default document type is empty.  However, if spider mode is
         on or time-stamping is employed, HEAD_ONLY commands is
         encoded within *dt.  */
//      if (send_head_first && !got_head)
//        *dt |= HEAD_ONLY;
//      else
//        *dt &= ~HEAD_ONLY;

      /* Decide whether or not to restart.  */
      if (force_full_retrieve)
        hstat.restval = hstat.len;
      else if (opt.start_pos >= 0)
        hstat.restval = opt.start_pos;
      else if (opt.always_rest
          && got_name
          && stat (hstat.local_file, &st) == 0
          && S_ISREG (st.st_mode))
        /* When -c is used, continue from on-disk size.  (Can't use
           hstat.len even if count>1 because we don't want a failed
           first attempt to clobber existing data.)  */
        hstat.restval = st.st_size;
      else if (count > 1)
        /* otherwise, continue where the previous try left off */
        hstat.restval = hstat.len;
      else
        hstat.restval = 0;

      /* Decide whether to send the no-cache directive.  We send it in
         two cases:
           a) we're using a proxy, and we're past our first retrieval.
              Some proxies are notorious for caching incomplete data, so
              we require a fresh get.
           b) caching is explicitly inhibited. */
//      if ((proxy && count > 1)        /* a */
//          || !opt.allow_cache)        /* b */
//        *dt |= SEND_NOCACHE;
//      else
//        *dt &= ~SEND_NOCACHE;

      /* Try fetching the document, or at least its head.  */
      err = gethttp (u, original_url, &hstat, dt, proxy, iri, count);

      /* Time?  */
      tms = datetime_str (time (NULL));

      /* Get the new location (with or without the redirection).  */
      if (hstat.newloc)
        *newloc = strdup (hstat.newloc);

      switch (err)
        {
        case HERR: case HEOF: case CONSOCKERR:
        case CONERROR: case READERR: case WRITEFAILED:
        case RANGEERR: case FOPEN_EXCL_ERR: case GATEWAYTIMEOUT:
          /* Non-fatal errors continue executing the loop, which will
             bring them to "while" statement at the end, to judge
             whether the number of tries was exceeded.  */
         // printwhat (count, opt.ntry);
          free (hstat.message);
          free (hstat.error);
          continue;
        case FWRITEERR: case FOPENERR:
          /* Another fatal error.  */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Cannot write to %s (%s).\n"),
                     quote (hstat.local_file), strerror (errno));
          ret = err;
          goto exit;
        case HOSTERR:
          /* Fatal unless option set otherwise. */
          if ( opt.retry_on_host_error )
            {
              printwhat (count, opt.ntry);
              free (hstat.message);
              free (hstat.error);
              continue;
            }
          ret = err;
          goto exit;
        case CONIMPOSSIBLE: case PROXERR: case SSLINITFAILED:
        case CONTNOTSUPPORTED: case VERIFCERTERR: case FILEBADFILE:
        case UNKNOWNATTR:
          /* Fatal errors just return from the function.  */
          ret = err;
          goto exit;
        case ATTRMISSING:
          /* A missing attribute in a Header is a fatal Protocol error. */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Required attribute missing from Header received.\n"));
          ret = err;
          goto exit;
        case AUTHFAILED:
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Username/Password Authentication Failed.\n"));
          ret = err;
          goto exit;
        case WARC_ERR:
          /* A fatal WARC error. */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Cannot write to WARC file.\n"));
          ret = err;
          goto exit;
        case WARC_TMP_FOPENERR: case WARC_TMP_FWRITEERR:
          /* A fatal WARC error. */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Cannot write to temporary WARC file.\n"));
          ret = err;
          goto exit;
        case CONSSLERR:
          /* Another fatal error.  */
          logprintf (LOG_NOTQUIET, _("Unable to establish SSL connection.\n"));
          ret = err;
          goto exit;
        case UNLINKERR:
          /* Another fatal error.  */
          logputs (LOG_VERBOSE, "\n");
          logprintf (LOG_NOTQUIET, _("Cannot unlink %s (%s).\n"),
                     quote (hstat.local_file), strerror (errno));
          ret = err;
          goto exit;
        case NEWLOCATION:
        case NEWLOCATION_KEEP_POST:
          /* Return the new location to the caller.  */
          if (!*newloc)
            {
              logprintf (LOG_NOTQUIET,
                         _("ERROR: Redirection (%d) without location.\n"),
                         hstat.statcode);
              ret = WRONGCODE;
            }
          else
            {
              ret = err;
            }
          goto exit;
        case RETRUNNEEDED:
          /* The file was already fully retrieved. */
          ret = RETROK;
          goto exit;
        case RETRFINISHED:
          /* Deal with you later.  */
          break;
#ifdef HAVE_METALINK
        case RETR_WITH_METALINK:
          {
            if (hstat.metalink == NULL)
              {
                logputs (LOG_NOTQUIET,
                         _("Could not find Metalink data in HTTP response. "
                           "Downloading file using HTTP GET.\n"));
                *dt &= ~METALINK_METADATA;
                *dt &= ~HEAD_ONLY;
                got_head = true;
                continue;
              }

            logputs (LOG_VERBOSE,
                     _("Metalink headers found. "
                       "Switching to Metalink mode.\n"));

            ret = retrieve_from_metalink (hstat.metalink);
            goto exit;
          }
          break;
#endif
        default:
          /* All possibilities should have been exhausted.  */
          abort ();
        }

      if (!(*dt & RETROKF))
        {
          char *hurl = NULL;
          if (!opt.verbose)
            {
              /* #### Ugly ugly ugly! */
              hurl = url_string (u, URL_AUTH_HIDE_PASSWD);
              logprintf (LOG_NONVERBOSE, "%s:\n", hurl);
            }

          /* Fall back to GET if HEAD fails with a 500 or 501 error code. */
          if (*dt & HEAD_ONLY
              && (hstat.statcode == 500 || hstat.statcode == 501))
            {
              got_head = true;
              free (hurl);
              continue;
            }
          /* Maybe we should always keep track of broken links, not just in
           * spider mode.
           * Don't log error if it was UTF-8 encoded because we will try
           * once unencoded. */
          else if (opt.spider && !iri->utf8_encode)
            {
              /* #### Again: ugly ugly ugly! */
              if (!hurl)
                hurl = url_string (u, URL_AUTH_HIDE_PASSWD);
              nonexisting_url (hurl);
              logprintf (LOG_NOTQUIET, _("\
Remote file does not exist -- broken link!!!\n"));
            }
          else if (check_retry_on_http_error (hstat.statcode))
            {
              printwhat (count, opt.ntry);
              free (hurl);
              continue;
            }
          else
            {
              logprintf (LOG_NOTQUIET, _("%s ERROR %d: %s.\n"),
                         tms, hstat.statcode,
                         quotearg_style (escape_quoting_style, hstat.error));
            }
          logputs (LOG_VERBOSE, "\n");
          ret = WRONGCODE;
          free (hurl);
          goto exit;
        }

      /* Did we get the time-stamp? */
      if (!got_head || (opt.spider && !opt.recursive))
        {
          got_head = true;    /* no more time-stamping */

          if (opt.timestamping && !hstat.remote_time)
            {
              logputs (LOG_NOTQUIET, _("\
Last-modified header missing -- time-stamps turned off.\n"));
            }
          else if (hstat.remote_time)
            {
              /* Convert the date-string into struct tm.  */
              tmr = http_atotm (hstat.remote_time);
              if (tmr == (time_t) (-1))
                logputs (LOG_VERBOSE, _("\
Last-modified header invalid -- time-stamp ignored.\n"));
              if (*dt & HEAD_ONLY)
                time_came_from_head = true;
            }

          if (send_head_first)
            {
              /* The time-stamping section.  */
              if (opt.timestamping)
                {
                  if (hstat.orig_file_name) /* Perform the following
                                               checks only if the file
                                               we're supposed to
                                               download already exists.  */
                    {
                      if (hstat.remote_time &&
                          tmr != (time_t) (-1))
                        {
                          /* Now time-stamping can be used validly.
                             Time-stamping means that if the sizes of
                             the local and remote file match, and local
                             file is newer than the remote file, it will
                             not be retrieved.  Otherwise, the normal
                             download procedure is resumed.  */
                          if (hstat.orig_file_tstamp >= tmr)
                            {
                              if (hstat.contlen == -1
                                  || hstat.orig_file_size == hstat.contlen)
                                {
                                  logprintf (LOG_VERBOSE, _("\
Server file no newer than local file %s -- not retrieving.\n\n"),
                                             quote (hstat.orig_file_name));
                                  ret = RETROK;
                                  goto exit;
                                }
                              else
                                {
                                  logprintf (LOG_VERBOSE, _("\
The sizes do not match (local %s) -- retrieving.\n"),
                                             number_to_static_string (hstat.orig_file_size));
                                }
                            }
                          else
                            {
                              force_full_retrieve = true;
                              logputs (LOG_VERBOSE,
                                       _("Remote file is newer, retrieving.\n"));
                            }

                          logputs (LOG_VERBOSE, "\n");
                        }
                    }

                  /* free_hstat (&hstat); */
                  hstat.timestamp_checked = true;
                }

              if (opt.spider)
                {
                  bool finished = true;
                  if (opt.recursive)
                    {
                      if ((*dt & TEXTHTML) || (*dt & TEXTCSS))
                        {
                          logputs (LOG_VERBOSE, _("\
Remote file exists and could contain links to other resources -- retrieving.\n\n"));
                          finished = false;
                        }
                      else
                        {
                          logprintf (LOG_VERBOSE, _("\
Remote file exists but does not contain any link -- not retrieving.\n\n"));
                          ret = RETROK; /* RETRUNNEEDED is not for caller. */
                        }
                    }
                  else
                    {
                      if ((*dt & TEXTHTML) || (*dt & TEXTCSS))
                        {
                          logprintf (LOG_VERBOSE, _("\
Remote file exists and could contain further links,\n\
but recursion is disabled -- not retrieving.\n\n"));
                        }
                      else
                        {
                          logprintf (LOG_VERBOSE, _("\
Remote file exists.\n\n"));
                        }
                      ret = RETROK; /* RETRUNNEEDED is not for caller. */
                    }

                  if (finished)
                    {
                      logprintf (LOG_NONVERBOSE,
                                 _("%s URL: %s %2d %s\n"),
                                 tms, u->url, hstat.statcode,
                                 hstat.message ? quotearg_style (escape_quoting_style, hstat.message) : "");
                      goto exit;
                    }
                }

              got_name = true;
              *dt &= ~HEAD_ONLY;
              count = 0;          /* the retrieve count for HEAD is reset */
              free (hstat.message);
              free (hstat.error);
              continue;
            } /* send_head_first */
        } /* !got_head */

      if (opt.useservertimestamps
          && (tmr != (time_t) (-1))
          && ((hstat.len == hstat.contlen) ||
              ((hstat.res == 0) && (hstat.contlen == -1))))
        {
          const char *fl = NULL;
          set_local_file (&fl, hstat.local_file);
          if (fl)
            {
              time_t newtmr = -1;
              /* Reparse time header, in case it's changed. */
              if (time_came_from_head
                  && hstat.remote_time && hstat.remote_time[0])
                {
                  newtmr = http_atotm (hstat.remote_time);
                  if (newtmr != (time_t)-1)
                    tmr = newtmr;
                }
              touch (fl, tmr);
            }
        }
      /* End of time-stamping section. */

      tmrate = retr_rate (hstat.rd_size, hstat.dltime);
      total_download_time += hstat.dltime;

      if (hstat.len == hstat.contlen)
        {
          if (*dt & RETROKF || opt.content_on_error)
            {
              bool write_to_stdout = (opt.output_document && HYPHENP (opt.output_document));

              logprintf (LOG_VERBOSE,
                         write_to_stdout
                         ? _("%s (%s) - written to stdout %s[%s/%s]\n\n")
                         : _("%s (%s) - %s saved [%s/%s]\n\n"),
                         tms, tmrate,
                         write_to_stdout ? "" : quote (hstat.local_file),
                         number_to_static_string (hstat.len),
                         number_to_static_string (hstat.contlen));
              logprintf (LOG_NONVERBOSE,
                         "%s URL:%s [%s/%s] -> \"%s\" [%d]\n",
                         tms, u->url,
                         number_to_static_string (hstat.len),
                         number_to_static_string (hstat.contlen),
                         hstat.local_file, count);
            }
          ++numurls;
          total_downloaded_bytes += hstat.rd_size;

          /* Remember that we downloaded the file for later ".orig" code. */
          if (*dt & ADDED_HTML_EXTENSION)
            downloaded_file (FILE_DOWNLOADED_AND_HTML_EXTENSION_ADDED, hstat.local_file);
          else
            downloaded_file (FILE_DOWNLOADED_NORMALLY, hstat.local_file);

          ret = RETROK;
          goto exit;
        }
      else if (hstat.res == 0) /* No read error */
        {
          if (hstat.contlen == -1)  /* We don't know how much we were supposed
                                       to get, so assume we succeeded. */
            {
              if (*dt & RETROKF || opt.content_on_error)
                {
                  bool write_to_stdout = (opt.output_document && HYPHENP (opt.output_document));

                  logprintf (LOG_VERBOSE,
                             write_to_stdout
                             ? _("%s (%s) - written to stdout %s[%s]\n\n")
                             : _("%s (%s) - %s saved [%s]\n\n"),
                             tms, tmrate,
                             write_to_stdout ? "" : quote (hstat.local_file),
                             number_to_static_string (hstat.len));
                  logprintf (LOG_NONVERBOSE,
                             "%s URL:%s [%s] -> \"%s\" [%d]\n",
                             tms, u->url, number_to_static_string (hstat.len),
                             hstat.local_file, count);
                }
              ++numurls;
              total_downloaded_bytes += hstat.rd_size;

              /* Remember that we downloaded the file for later ".orig" code. */
              if (*dt & ADDED_HTML_EXTENSION)
                downloaded_file (FILE_DOWNLOADED_AND_HTML_EXTENSION_ADDED, hstat.local_file);
              else
                downloaded_file (FILE_DOWNLOADED_NORMALLY, hstat.local_file);

              ret = RETROK;
              goto exit;
            }
          else if (hstat.len < hstat.contlen) /* meaning we lost the
                                                 connection too soon */
            {
              logprintf (LOG_VERBOSE,
                         _("%s (%s) - Connection closed at byte %s. "),
                         tms, tmrate, number_to_static_string (hstat.len));
              printwhat (count, opt.ntry);
              continue;
            }
          else if (hstat.len != hstat.restval)
            /* Getting here would mean reading more data than
               requested with content-length, which we never do.  */
            abort ();
          else
            {
              /* Getting here probably means that the content-length was
               * _less_ than the original, local size. We should probably
               * truncate or re-read, or something. FIXME */
              ret = RETROK;
              goto exit;
            }
        }
      else /* from now on hstat.res can only be -1 */
        {
          if (hstat.contlen == -1)
            {
              logprintf (LOG_VERBOSE,
                         _("%s (%s) - Read error at byte %s (%s)."),
                         tms, tmrate, number_to_static_string (hstat.len),
                         hstat.rderrmsg);
              printwhat (count, opt.ntry);
              continue;
            }
          else /* hstat.res == -1 and contlen is given */
            {
              logprintf (LOG_VERBOSE,
                         _("%s (%s) - Read error at byte %s/%s (%s). "),
                         tms, tmrate,
                         number_to_static_string (hstat.len),
                         number_to_static_string (hstat.contlen),
                         hstat.rderrmsg);
              printwhat (count, opt.ntry);
              continue;
            }
        }
      /* not reached */
    }
  while (!opt.ntry || (count < opt.ntry));

exit:
  if ((ret == RETROK || opt.content_on_error) && local_file)
    {
      free (*local_file);
      /* Bugfix: Prevent SIGSEGV when hstat.local_file was left NULL
         (i.e. due to opt.content_disposition).  */
      if (hstat.local_file)
        *local_file = xstrdup (hstat.local_file);
    }
  free_hstat (&hstat);

  return ret;
}
