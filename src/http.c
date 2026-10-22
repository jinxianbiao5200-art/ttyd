#include <libwebsockets.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zlib.h>

#include "html.h"
#include "server.h"
#include "utils.h"

enum { AUTH_OK, AUTH_FAIL, AUTH_ERROR };

static char *html_cache = NULL;
static size_t html_cache_len = 0;

static int send_unauthorized(struct lws *wsi, unsigned int code, enum lws_token_indexes header) {
  unsigned char buffer[1024 + LWS_PRE], *p, *end;
  p = buffer + LWS_PRE;
  end = p + sizeof(buffer) - LWS_PRE;

  if (lws_add_http_header_status(wsi, code, &p, end) ||
      lws_add_http_header_by_token(wsi, header, (unsigned char *)"Basic realm=\"ttyd\"", 18, &p, end) ||
      lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return AUTH_FAIL;

  return lws_http_transaction_completed(wsi) ? AUTH_FAIL : AUTH_ERROR;
}

static int check_auth(struct lws *wsi, struct pss_http *pss) {
  if (server->auth_header != NULL) {
    if (lws_hdr_custom_length(wsi, server->auth_header, strlen(server->auth_header)) > 0) return AUTH_OK;
    return send_unauthorized(wsi, HTTP_STATUS_PROXY_AUTH_REQUIRED, WSI_TOKEN_HTTP_PROXY_AUTHENTICATE);
  }

  if(server->credential != NULL) {
    char buf[256];
    int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_AUTHORIZATION);
    if (len >= 7 && strstr(buf, "Basic ")) {
      if (!strcmp(buf + 6, server->credential)) return AUTH_OK;
    }
    return send_unauthorized(wsi, HTTP_STATUS_UNAUTHORIZED, WSI_TOKEN_HTTP_WWW_AUTHENTICATE);
  }

  return AUTH_OK;
}

static bool accept_gzip(struct lws *wsi) {
  char buf[256];
  int len = lws_hdr_copy(wsi, buf, sizeof(buf), WSI_TOKEN_HTTP_ACCEPT_ENCODING);
  return len > 0 && strstr(buf, "gzip") != NULL;
}

static bool uncompress_html(char **output, size_t *output_len) {
  if (html_cache == NULL || html_cache_len == 0) {
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    if (inflateInit2(&stream, 16 + 15) != Z_OK) return false;

    html_cache_len = index_html_size;
    html_cache = xmalloc(html_cache_len);

    stream.avail_in = index_html_len;
    stream.avail_out = html_cache_len;
    stream.next_in = (void *)index_html;
    stream.next_out = (void *)html_cache;

    int ret = inflate(&stream, Z_SYNC_FLUSH);
    inflateEnd(&stream);
    if (ret != Z_STREAM_END) {
      free(html_cache);
      html_cache = NULL;
      html_cache_len = 0;
      return false;
    }
  }

  *output = html_cache;
  *output_len = html_cache_len;

  return true;
}

static void pss_buffer_free(struct pss_http *pss) {
  if (pss->buffer != (char *)index_html && pss->buffer != html_cache) free(pss->buffer);
}

static void access_log(struct lws *wsi, const char *path) {
  char rip[50];

  lws_get_peer_simple(lws_get_network_wsi(wsi), rip, sizeof(rip));
  lwsl_notice("HTTP %s - %s\n", path, rip);
}


#define UPLOAD_MAX_BYTES (20 * 1024 * 1024)

static void upload_cleanup(struct pss_http *pss) {
  if (pss->upload_fp != NULL) {
    fclose(pss->upload_fp);
    pss->upload_fp = NULL;
    if (pss->upload_tmp[0]) unlink(pss->upload_tmp);
  }
  pss->upload_tmp[0] = '\0';
}

static int send_json(struct lws *wsi, struct pss_http *pss, unsigned int status, const char *json) {
  unsigned char buffer[1024 + LWS_PRE], *p = buffer + LWS_PRE, *end = buffer + sizeof(buffer);
  size_t n = strlen(json);
  if (lws_add_http_header_status(wsi, status, &p, end) ||
      lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (unsigned char *)"application/json;charset=utf-8",
                                   30, &p, end) ||
      lws_add_http_header_content_length(wsi, (unsigned long)n, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
      lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
    return 1;
  pss->buffer = pss->ptr = strdup(json);
  pss->len = n;
  lws_callback_on_writable(wsi);
  return 0;
}

// returns 0 to wait for body, 1 on fatal error, -2 if response already sent
static int upload_begin(struct lws *wsi, struct pss_http *pss) {
  char ctype[128] = {0}, clen[32] = {0};
  const char *ext = NULL;
  if (lws_hdr_total_length(wsi, WSI_TOKEN_POST_URI) <= 0) {
    lws_return_http_status(wsi, HTTP_STATUS_METHOD_NOT_ALLOWED, NULL);
    return -2;
  }
  if (!server->writable) {
    lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
    return -2;
  }
  lws_hdr_copy(wsi, ctype, sizeof(ctype), WSI_TOKEN_HTTP_CONTENT_TYPE);
  if (strncasecmp(ctype, "image/png", 9) == 0) ext = "png";
  else if (strncasecmp(ctype, "image/jpeg", 10) == 0) ext = "jpg";
  else if (strncasecmp(ctype, "image/gif", 9) == 0) ext = "gif";
  else if (strncasecmp(ctype, "image/webp", 10) == 0) ext = "webp";
  else if (strncasecmp(ctype, "image/", 6) == 0) ext = "img";
  if (ext == NULL) {
    lws_return_http_status(wsi, HTTP_STATUS_UNSUPPORTED_MEDIA_TYPE, NULL);
    return -2;
  }
  if (lws_hdr_copy(wsi, clen, sizeof(clen), WSI_TOKEN_HTTP_CONTENT_LENGTH) > 0 &&
      strtoull(clen, NULL, 10) > UPLOAD_MAX_BYTES) {
    lws_return_http_status(wsi, HTTP_STATUS_REQ_ENTITY_TOO_LARGE, NULL);
    return -2;
  }
  const char *home = getenv("HOME");
  if (home == NULL || home[0] != '/') home = "/tmp";
  char dir[400];
  snprintf(dir, sizeof(dir), "%s/Downloads", home);
  mkdir(dir, 0755);
  snprintf(dir, sizeof(dir), "%s/Downloads/ttyd-paste", home);
  if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
    lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    return -2;
  }
  char ts[32];
  time_t now = time(NULL);
  struct tm tm;
  localtime_r(&now, &tm);
  strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", &tm);
  struct stat st;
  snprintf(pss->upload_path, sizeof(pss->upload_path), "%s/paste-%s.%s", dir, ts, ext);
  for (int i = 2; stat(pss->upload_path, &st) == 0 && i < 100; i++)
    snprintf(pss->upload_path, sizeof(pss->upload_path), "%s/paste-%s-%d.%s", dir, ts, i, ext);
  snprintf(pss->upload_tmp, sizeof(pss->upload_tmp), "%s/.upload-XXXXXX", dir);
  int fd = mkstemp(pss->upload_tmp);
  if (fd < 0 || (pss->upload_fp = fdopen(fd, "wb")) == NULL) {
    if (fd >= 0) close(fd);
    pss->upload_tmp[0] = '\0';
    lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
    return -2;
  }
  pss->upload_len = 0;
  pss->upload_err = false;
  return 0;
}

int callback_http(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len) {
  struct pss_http *pss = (struct pss_http *)user;
  unsigned char buffer[4096 + LWS_PRE], *p, *end;
  char buf[256];
  bool done = false;

  switch (reason) {
    case LWS_CALLBACK_HTTP:
      access_log(wsi, (const char *)in);
      snprintf(pss->path, sizeof(pss->path), "%s", (const char *)in);
      switch (check_auth(wsi, pss)) {
        case AUTH_OK:
          break;
        case AUTH_FAIL:
          return 0;
        case AUTH_ERROR:
        default:
          return 1;
      }

      p = buffer + LWS_PRE;
      end = p + sizeof(buffer) - LWS_PRE;

      snprintf(buf, sizeof(buf), "%s/upload", endpoints.parent);
      if (strcmp(pss->path, buf) == 0) {
        int r = upload_begin(wsi, pss);
        if (r == -2) goto try_to_reuse;
        return r;
      }

      if (strcmp(pss->path, endpoints.token) == 0) {
        const char *credential = server->credential != NULL ? server->credential : "";
        size_t n = snprintf(buf, sizeof(buf), "{\"token\": \"%s\"}", credential);
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE,
                                         (unsigned char *)"application/json;charset=utf-8", 30, &p, end) ||
            lws_add_http_header_content_length(wsi, (unsigned long)n, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

        pss->buffer = pss->ptr = strdup(buf);
        pss->len = n;
        lws_callback_on_writable(wsi);
        break;
      }

      // redirects `/base-path` to `/base-path/`
      if (strcmp(pss->path, endpoints.parent) == 0) {
        if (lws_add_http_header_status(wsi, HTTP_STATUS_FOUND, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_LOCATION, (unsigned char *)endpoints.index,
                                         (int)strlen(endpoints.index), &p, end) ||
            lws_add_http_header_content_length(wsi, 0, &p, end) || lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;
        goto try_to_reuse;
      }

      if (strcmp(pss->path, endpoints.index) != 0) {
        lws_return_http_status(wsi, HTTP_STATUS_NOT_FOUND, NULL);
        goto try_to_reuse;
      }

      const char *content_type = "text/html";
      if (server->index != NULL) {
        int n = lws_serve_http_file(wsi, server->index, content_type, NULL, 0);
        if (n < 0 || (n > 0 && lws_http_transaction_completed(wsi))) return 1;
      } else {
        char *output = (char *)index_html;
        size_t output_len = index_html_len;
        if (lws_add_http_header_status(wsi, HTTP_STATUS_OK, &p, end) ||
            lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_TYPE, (const unsigned char *)content_type, 9, &p,
                                         end))
          return 1;
#ifdef LWS_WITH_HTTP_STREAM_COMPRESSION
        if (!uncompress_html(&output, &output_len)) return 1;
#else
        if (accept_gzip(wsi)) {
          if (lws_add_http_header_by_token(wsi, WSI_TOKEN_HTTP_CONTENT_ENCODING, (unsigned char *)"gzip", 4, &p, end))
            return 1;
        } else {
          if (!uncompress_html(&output, &output_len)) return 1;
        }
#endif

        if (lws_add_http_header_content_length(wsi, (unsigned long)output_len, &p, end) ||
            lws_finalize_http_header(wsi, &p, end) ||
            lws_write(wsi, buffer + LWS_PRE, p - (buffer + LWS_PRE), LWS_WRITE_HTTP_HEADERS) < 0)
          return 1;

        pss->buffer = pss->ptr = output;
        pss->len = output_len;
        lws_callback_on_writable(wsi);
      }
      break;

    case LWS_CALLBACK_HTTP_WRITEABLE:
      if (!pss->buffer || pss->len == 0) {
        goto try_to_reuse;
      }

      do {
        int n = sizeof(buffer) - LWS_PRE;
        int m = lws_get_peer_write_allowance(wsi);
        if (m == 0) {
          lws_callback_on_writable(wsi);
          return 0;
        } else if (m != -1 && m < n) {
          n = m;
        }
        if (pss->ptr + n > pss->buffer + pss->len) {
          n = (int)(pss->len - (pss->ptr - pss->buffer));
          done = true;
        }
        memcpy(buffer + LWS_PRE, pss->ptr, n);
        pss->ptr += n;
        if (lws_write_http(wsi, buffer + LWS_PRE, (size_t)n) < n) {
          pss_buffer_free(pss);
          return -1;
        }
      } while (!lws_send_pipe_choked(wsi) && !done);

      if (!done && pss->ptr < pss->buffer + pss->len) {
        lws_callback_on_writable(wsi);
        break;
      }

      pss_buffer_free(pss);
      goto try_to_reuse;

    case LWS_CALLBACK_HTTP_BODY:
      if (pss == NULL || pss->upload_fp == NULL) break;
      if (pss->upload_err) break;
      pss->upload_len += len;
      if (pss->upload_len > UPLOAD_MAX_BYTES || fwrite(in, 1, len, pss->upload_fp) != len) pss->upload_err = true;
      break;

    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
      if (pss == NULL || pss->upload_fp == NULL) break;
      if (pss->upload_err || pss->upload_len == 0 || fclose(pss->upload_fp) != 0) {
        bool too_big = pss->upload_len > UPLOAD_MAX_BYTES;
        upload_cleanup(pss);
        lws_return_http_status(wsi, too_big ? HTTP_STATUS_REQ_ENTITY_TOO_LARGE : HTTP_STATUS_BAD_REQUEST, NULL);
        goto try_to_reuse;
      }
      pss->upload_fp = NULL;
      if (rename(pss->upload_tmp, pss->upload_path) != 0) {
        unlink(pss->upload_tmp);
        pss->upload_tmp[0] = '\0';
        lws_return_http_status(wsi, HTTP_STATUS_INTERNAL_SERVER_ERROR, NULL);
        goto try_to_reuse;
      }
      pss->upload_tmp[0] = '\0';
      chmod(pss->upload_path, 0600);
      lwsl_notice("image uploaded: %s (%zu bytes)\n", pss->upload_path, pss->upload_len);
      {
        char json[700];
        snprintf(json, sizeof(json), "{\"path\": \"%s\"}", pss->upload_path);
        if (send_json(wsi, pss, HTTP_STATUS_OK, json)) return 1;
      }
      break;

    case LWS_CALLBACK_CLOSED_HTTP:
      if (pss != NULL) upload_cleanup(pss);
      break;

    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
      goto try_to_reuse;
#if (defined(LWS_OPENSSL_SUPPORT) || defined(LWS_WITH_TLS)) && !defined(LWS_WITH_MBEDTLS)
    case LWS_CALLBACK_OPENSSL_PERFORM_CLIENT_CERT_VERIFICATION:
      if (!len || (SSL_get_verify_result((SSL *)in) != X509_V_OK)) {
        int err = X509_STORE_CTX_get_error((X509_STORE_CTX *)user);
        int depth = X509_STORE_CTX_get_error_depth((X509_STORE_CTX *)user);
        const char *msg = X509_verify_cert_error_string(err);
        lwsl_err("client certificate verification error: %s (%d), depth: %d\n", msg, err, depth);
        return 1;
      }
      break;
#endif
    default:
      break;
  }

  return 0;

  /* if we're on HTTP1.1 or 2.0, will keep the idle connection alive */
try_to_reuse:
  if (lws_http_transaction_completed(wsi)) return -1;

  return 0;
}
