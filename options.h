#ifndef OPTIONS_H
#define OPTIONS_H

#include <stdbool.h>
#include <stdio.h>

struct options
{
  bool ignore_length;           /* Do we heed content-length at all?  */
  bool spanhost;                /* Do we span across hosts in
                                   recursion? */
 // int  max_redirect;            /* Maximum number of times we'll allow
                                  // a page to redirect. */
//  bool no_parent;               /* Restrict access to the parent
//                                   directory.  */
//  int reclevel;                 /* Maximum level of recursion */
//  bool dirstruct;               /* Do we build the directory structure
//                                   as we go along? */
//  bool no_dirstruct;            /* Do we hate dirstruct? */
//  int cut_dirs;                 /* Number of directory components to cut. */
//  bool add_hostdir;             /* Do we add hostname directory? */
//  bool protocol_directories;    /* Whether to prepend "http"/"ftp" to dirs. */
//  bool noclobber;               /* Disables clobbering of existing data. */
//  bool unlink_requested;        /* remove file before clobbering */
//  char *dir_prefix;             /* The top of directory tree */
//  char *lfilename;              /* Log filename */
  char *input_filename;         /* Input filename */
//#ifdef HAVE_METALINK
//  char *input_metalink;         /* Input metalink file */
//  int metalink_index;           /* Metalink application/metalink4+xml metaurl ordinal number. */
//  bool metalink_over_http;      /* Use Metalink if present in HTTP response */
//  char *preferred_location;     /* Preferred location for Metalink resources */
//#endif
  char *choose_config;          /* Specified config file */
  //bool noconfig;                /* Ignore all config files? */
  bool force_html;              /* Is the input file an HTML file? */

  char *default_page;           /* Alternative default page (index file) */

//  bool spider;                  /* Is Wget in spider mode? */
//no regex
//  char **accepts;               /* List of patterns to accept. */
//  char **rejects;               /* List of patterns to reject. */
//  const char **excludes;        /* List of excluded FTP directories. */
//  const char **includes;        /* List of FTP directories to
//                                   follow. */
//  bool ignore_case;             /* Whether to ignore case when
//                                   matching dirs and files */

//  char *acceptregex_s;          /* Patterns to accept (a regex string). */
//  char *rejectregex_s;          /* Patterns to reject (a regex string). */
//  void *acceptregex;            /* Patterns to accept (a regex struct). */
//  void *rejectregex;            /* Patterns to reject (a regex struct). */
//  void *(*regex_compile_fun)(const char *);             /* Function to compile a regex. */
//  bool (*regex_match_fun)(const void *, const char *);  /* Function to match a string to a regex. */

  char **domains;               /* See host.c */
  char **exclude_domains;
  //bool dns_cache;               /* whether we cache DNS lookups. */

  char **follow_tags;           /* List of HTML tags to recursively follow. */
  char **ignore_tags;           /* List of HTML tags to ignore if recursing. */

//  bool follow_ftp;              /* Are FTP URL-s followed in recursive
//                                   retrieving? */
//  bool retr_symlinks;           /* Whether we retrieve symlinks in
//                                   FTP. */
  char *output_document;        /* The output file to which the
                                   documents will be printed.  */
//  char *warc_filename;          /* WARC output filename */
//  char *warc_tempdir;           /* WARC temp dir */
//  char *warc_cdx_dedup_filename;/* CDX file to be used for deduplication. */
//  wgint warc_maxsize;           /* WARC max archive size */
//  bool warc_compression_enabled;/* For GZIP compression. */
//  bool warc_digests_enabled;    /* For SHA1 digests. */
//  bool warc_cdx_enabled;        /* Create CDX files? */
//  bool warc_keep_log;           /* Store the log file in a WARC record. */
//  char **warc_user_headers;     /* User-defined WARC header(s). */

//  bool enable_xattr;            /* Store metadata in POSIX extended attributes. */

//  char *user;                   /* Generic username */
//  char *passwd;                 /* Generic password */
//  bool ask_passwd;              /* Ask for password? */
//  char *use_askpass;           /* value to use for use-askpass if WGET_ASKPASS is not set */

//  bool always_rest;             /* Always use REST. */
//  wgint start_pos;              /* Start position of a download. */
//  char *ftp_user;               /* FTP username */
//  char *ftp_passwd;             /* FTP password */
//  bool netrc;                   /* Whether to read .netrc. */
//  bool ftp_glob;                /* FTP globbing */
//  bool ftp_pasv;                /* Passive FTP. */

//  char *http_user;              /* HTTP username. */
//  char *http_passwd;            /* HTTP password. */
//  char **user_headers;          /* User-defined header(s). */
//  bool http_keep_alive;         /* whether we use keep-alive */

//  bool use_proxy;               /* Do we use proxy? */
//  bool allow_cache;             /* Do we allow server-side caching? */
//  char *http_proxy, *ftp_proxy, *https_proxy; //no proxy
//  char **no_proxy;
  char *base_href;
//  char *progress_type;          /* progress indicator type. */
//  int  show_progress;           /* Show only the progress bar */
//  bool noscroll;                /* Don't scroll the filename in the progressbar */
//  char *proxy_user; /*oli*/
//  char *proxy_passwd;

  double read_timeout;          /* The read/write timeout. */
  double dns_timeout;           /* The DNS timeout. */
  double connect_timeout;       /* The connect timeout. */

  bool random_wait;             /* vary from 0 .. wait secs by random()? */
  double wait;                  /* The wait period between retrievals. */
  double waitretry;             /* The wait period between retries. - HEH */
//  bool use_robots;              /* Do we heed robots.txt? */

//  wgint limit_rate;             /* Limit the download rate to this
//                                   many bps. */
//  SUM_SIZE_INT quota;           /* Maximum file size to download and
//                                   store. */

  bool server_response;         /* Do we print server response? */
  bool save_headers;            /* Do we save headers together with
                                   file? */
  bool content_on_error;        /* Do we output the content when the HTTP
                                   status code indicates a server error */

//  bool debug;                   /* Debugging on/off */

//  bool timestamping;            /* Whether to use time-stamping. */
//  bool if_modified_since;       /* Whether to use conditional get requests.  */

//  bool backup_converted;        /* Do we save pre-converted files as *.orig? */
//  int backups;                  /* Are numeric backups made? */

//  char *useragent;              /* User-Agent string, which can be set
//                                   to something other than Wget. */
//  char *referer;                /* Naughty Referer, which can be
//                                   set to something other than
//                                   NULL. */
  bool convert_links;           /* Will the links be converted
                                   locally? */
  bool convert_file_only;       /* Convert only the file portion of the URI (i.e. basename).
                                   Leave everything else untouched. */

  bool remove_listing;          /* Do we remove .listing files
                                   generated by FTP? */
 //bool htmlify;                 /* Do we HTML-ify the OS-dependent
   //                                listings? */

  char *dot_style;
//  wgint dot_bytes;              /* How many bytes in a printing
//                                   dot. */
//  int dots_in_line;             /* How many dots in one line. */
//  int dot_spacing;              /* How many dots between spacings. */

//  bool delete_after;            /* Whether the files will be deleted
//                                   after download. */

  bool adjust_extension;        /* Use ".html" extension on all text/html? */

  bool page_requisites;         /* Whether we need to download all files
                                   necessary to display a page properly. */
  char *bind_address;           /* What local IP address to bind to. */

//#ifdef HAVE_SSL
//  enum {
//    secure_protocol_auto,
//    secure_protocol_sslv2,
//    secure_protocol_sslv3,
//    secure_protocol_tlsv1,
//    secure_protocol_tlsv1_1,
//    secure_protocol_tlsv1_2,
//    secure_protocol_tlsv1_3,
//    secure_protocol_pfs
//  } secure_protocol;            /* type of secure protocol to use. */
//  int check_cert;               /* whether to validate the server's cert */
//  char *cert_file;              /* external client certificate to use. */
//  char *private_key;            /* private key file (if not internal). */
//  enum keyfile_type {
//    keyfile_pem,
//    keyfile_asn1
//  } cert_type;                  /* type of client certificate file */
//  enum keyfile_type
//    private_key_type;           /* type of private key file */

//  char *ca_directory;           /* CA directory (hash files) */
//  char *ca_cert;                /* CA certificate file to use */
//  char *crl_file;               /* file with CRLs */

//  char *pinnedpubkey;           /* Public key (PEM/DER) file, or any number
//                                   of base64 encoded sha256 hashes preceded by
//                                   \'sha256//\' and separated by \';\', to verify
//                                   peer against */

//  char *random_file;            /* file with random data to seed the PRNG */
//  char *egd_file;               /* file name of the egd daemon socket */
//  bool https_only;              /* whether to follow HTTPS only */
//  bool ftps_resume_ssl;
//  bool ftps_fallback_to_ftp;
//  bool ftps_implicit;
//  bool ftps_clear_data_connection;

//  char *tls_ciphers_string;
//#endif /* HAVE_SSL */

//  bool cookies;                 /* whether cookies are used. */
//  char *cookies_input;          /* file we're loading the cookies from. */
//  char *cookies_output;         /* file we're saving the cookies to. */
//  bool keep_badhash;            /* Keep files with checksum mismatch. */
//  bool keep_session_cookies;    /* whether session cookies should be
//                                   saved and loaded. */

//  char *post_data;              /* POST query string */
//  char *post_file_name;         /* File to post */
  char *method;                 /* HTTP Method to use in Header */
  char *body_data;              /* HTTP Method Data String */
  char *body_file;              /* HTTP Method File */

//  enum {
//    restrict_unix,
//    restrict_vms,
//    restrict_windows
//  } restrict_files_os;          /* file name restriction ruleset. */
//  bool restrict_files_ctrl;     /* non-zero if control chars in URLs
//                                   are restricted from appearing in
//                                   generated file names. */
//  bool restrict_files_nonascii; /* non-zero if bytes with values greater
//                                   than 127 are restricted. */
//  enum {
//    restrict_no_case_restriction,
//    restrict_lowercase,
//    restrict_uppercase
//  } restrict_files_case;        /* file name case restriction. */

//  bool strict_comments;         /* whether strict SGML comments are
//                                   enforced.  */

//  bool preserve_perm;           /* whether remote permissions are used
//                                   or that what is set by umask. */
  enum {
    prefer_ipv4, //ONLY
    prefer_ipv6,
    prefer_none
  } prefer_family;              /* preferred address family when more
                                   than one type is available */

  bool content_disposition;     /* Honor HTTP Content-Disposition header. */
  bool auth_without_challenge;  /* Issue Basic authentication creds without
                                   waiting for a challenge. */

  bool enable_iri;
//  char *encoding_remote;
  const char *locale;

  bool trustservernames;

  bool useservertimestamps;     /* Update downloaded files' timestamps to
                                   match those on server? */
  bool show_all_dns_entries;    /* Show all the DNS entries when resolving a
                                   name. */
//  bool report_bps;              /*Output bandwidth in bits format*/

//  char *rejected_log;           /* The file to log rejected URLS to. */

  const char *homedir;          /* the homedir of the running process */
  const char *wgetrcfile;       /* the wgetrc file to be loaded */
};


#endif // OPTIONS_H
