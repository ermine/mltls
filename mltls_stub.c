/*
 * (c) 2007-2008 Anastasia Gornostaeva <ermine@ermine.pp.ru>
 */

#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/signals.h>
#include <caml/callback.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_Val(v)             *((SSL **) Data_custom_val(v))
#define SSL_CTX_Val(v)         *((SSL_CTX**)Data_custom_val(v))
#define BIO_Val(v)             *((BIO **) Data_custom_val(v))

#define X509_Val(v)            *((X509 **) &Field(v, 0))
#define RSA_Val(v)             *((RSA **) &Field(v, 0))

static void finalize_ssl(value block) {
  SSL* ssl = SSL_Val(block);
  caml_enter_blocking_section();
  SSL_free(ssl);
  caml_leave_blocking_section();
}

static struct custom_operations ssl_ops = {
  "caml_ssl",
  finalize_ssl,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

static void finalize_ssl_ctx(value block) {
  SSL_CTX* ssl_ctx = SSL_CTX_Val(block);
  caml_enter_blocking_section();
  SSL_CTX_free(ssl_ctx);
  caml_leave_blocking_section();
}

static struct custom_operations ssl_ctx_ops = {
  "caml_ssl_ctx",
  finalize_ssl_ctx,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

static void finalize_bio(value block) {
  BIO* bio = BIO_Val(block);
  caml_enter_blocking_section();
  BIO_free(bio);
  caml_leave_blocking_section();
}

static struct custom_operations bio_ops = {
  "caml_bio",
  finalize_bio,
  custom_compare_default,
  custom_hash_default,
  custom_serialize_default,
  custom_deserialize_default
};

static value *mltls_error_exn = NULL;

/* SSL_library_init() always returns "1", so it is safe to discard the
   return value. 
*/
CAMLprim value camltls_init(value unit) {
  CAMLparam0();
  
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  SSL_load_error_strings();

  mltls_error_exn = caml_named_value("Mltls_Error");
  if (mltls_error_exn == NULL)
    caml_invalid_argument("Exception Mltls_Error is not initialized");

  CAMLreturn0;
}

static void mltls_error(char* fn, char* msg) {
  value res;

  if (msg == NULL)
    msg = "";
  res = alloc_small(3, 0);
  Field(res, 0) = *mltls_error_exn;
  Field(res, 1) = copy_string(fn);
  Field(res, 2) = copy_string(msg);
  mlraise(res);
}

CAMLprim value camltls_ERR_load_crypto_strings(value unit) {
  CAMLparam0();
  ERR_load_crypto_strings();
  CAMLreturn0;
}

CAMLprim value camltls_ERR_get_error(value unit) {
  CAMLparam0();
  CAMLlocal1(vres);
  long ret;
  caml_enter_blocking_section();
  ret = ERR_get_error();
  caml_leave_blocking_section();
  vres = Val_long(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_ERR_error_string_n(value ve) {
  CAMLparam1(ve);
  CAMLlocal1(vres);
  char buf[1024];
  ERR_error_string_n(Long_val(ve), buf, sizeof(buf));
  vres = copy_string(buf);
  CAMLreturn(vres);
}

#define tls_SSLv2_method           0
#define tls_SSLv2_server_method    1
#define tls_SSLv2_client_method    2
#define tls_SSLv3_method           3
#define tls_SSLv3_server_method    4
#define tls_SSLv3_client_method    5
#define tls_TLSv1_method           6
#define tls_TLSv1_server_method    7
#define tls_TLSv1_client_method    8
#define tls_SSLv23_method          9
#define tls_SSLv23_server_method   10
#define tls_SSLv23_client_method   11

static SSL_METHOD* get_method(int method) {
  switch(method) {
  case tls_SSLv2_method:         return SSLv2_method();
  case tls_SSLv2_server_method:  return SSLv2_server_method();
  case tls_SSLv2_client_method:  return SSLv2_client_method();
  case tls_SSLv3_method:         return SSLv3_method();
  case tls_SSLv3_server_method:  return SSLv3_server_method();
  case tls_SSLv3_client_method:  return SSLv3_client_method();
  case tls_TLSv1_method:         return TLSv1_method();
  case tls_TLSv1_server_method:  return TLSv1_server_method();
  case tls_TLSv1_client_method:  return TLSv1_client_method();
  case tls_SSLv23_method:        return SSLv23_method();
  case tls_SSLv23_server_method: return SSLv23_server_method();
  case tls_SSLv23_client_method: return SSLv23_client_method();
  default: caml_invalid_argument("Unknown method");
  }
}

CAMLprim value camltls_SSL_CTX_new (value vmethod) {
  CAMLparam1(vmethod);
  CAMLlocal1(vres);
  SSL_METHOD* method;
  SSL_CTX* ssl_ctx;
  int m = Int_val(vmethod);
  caml_enter_blocking_section();
  method = get_method(m);
  ssl_ctx = SSL_CTX_new(method);
  if(ssl_ctx == NULL) {
    caml_leave_blocking_section ();
    mltls_error("SSL_CTX_new", "Unable to create SSL_CTX structure");
  }
  caml_leave_blocking_section();
  vres = caml_alloc_custom(&ssl_ctx_ops, sizeof(SSL_CTX*), 0, 1);
  SSL_CTX_Val(vres) = ssl_ctx;
  CAMLreturn(vres);
}

static int get_file_type(value vtype) {
  CAMLparam1(vtype);
  switch(Int_val(vtype)) {
  case 0: return SSL_FILETYPE_PEM;
  case 1: return SSL_FILETYPE_ASN1;
  }
}

CAMLprim value camltls_SSL_CTX_use_certificate_file(value vctx, 
                                                    value vfile, value vtype) {

  CAMLparam3(vctx, vfile, vtype);
  CAMLlocal1(vres);
  int ret;
  SSL_CTX* ssl_ctx = SSL_CTX_Val(vctx);
  char* filename = String_val(vfile);
  caml_enter_blocking_section();
  ret = SSL_CTX_use_certificate_file(ssl_ctx, filename, get_file_type(vtype));
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_CTX_use_PrivateKey_file(value vctx,
                                                   value vfile, value vtype) {
  CAMLparam3(vctx, vfile, vtype);
  CAMLlocal1(vres);
  SSL_CTX* ssl_ctx = SSL_CTX_Val(vctx);
  char* filename = String_val(vfile);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_CTX_use_PrivateKey_file(ssl_ctx, filename, get_file_type(vtype));
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_new(value v) {
  CAMLparam1(v);
  CAMLlocal1(vres);
  SSL* ssl;
  SSL_CTX* ssl_ctx = SSL_CTX_Val(v);
  caml_enter_blocking_section();
  ssl = SSL_new(ssl_ctx);
  if(!ssl) {
    caml_leave_blocking_section();
    mltls_error("SSL_new", "Unable to create SSL structure");
  }
  caml_leave_blocking_section();
  vres = caml_alloc_custom(&ssl_ops, sizeof(SSL*), 0, 1);
  SSL_Val(vres) = ssl;
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_set_fd(value vssl, value vfd) {
  CAMLparam2(vssl, vfd);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int fd = Int_val(vfd);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_set_fd(ssl, fd);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_set_rfd(value vssl, value vfd) {
  CAMLparam2(vssl, vfd);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int fd = Int_val(vfd);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_set_rfd(ssl, fd);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_set_wfd(value vssl, value vfd) {
  CAMLparam2(vssl, vfd);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int fd = Int_val(vfd);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_set_wfd(ssl, fd);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_set_bio(value vssl, value vrbio, value vwbio) {
  CAMLparam3(vssl, vrbio, vwbio);
  SSL* ssl = SSL_Val(vssl);
  BIO* rbio = BIO_Val(vrbio);
  BIO* wbio = BIO_Val(vwbio);
  caml_enter_blocking_section();
  SSL_set_bio(ssl, rbio, wbio);
  caml_leave_blocking_section();
  CAMLreturn0;
}

CAMLprim value camltls_SSL_set_accept_state(value vssl) {
  CAMLparam1(vssl);
  SSL* ssl = SSL_Val(vssl);
  caml_enter_blocking_section();
  SSL_set_accept_state(ssl);
  caml_leave_blocking_section();
  CAMLreturn0;
}

CAMLprim value camltls_SSL_set_connect_state(value vssl) {
  CAMLparam1(vssl);
  SSL* ssl = SSL_Val(vssl);
  caml_enter_blocking_section();
  SSL_set_connect_state(ssl);
  caml_leave_blocking_section();
  CAMLreturn0;
}

CAMLprim value camltls_SSL_is_init_finished(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_is_init_finished(ssl);
  caml_leave_blocking_section();
  vres = Val_bool(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_accept(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_accept(ssl);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_connect(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  ret = SSL_connect(ssl);
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim camltls_SSL_do_handshake(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_do_handshake(ssl);
  caml_leave_blocking_section();
  vres = Val_bool(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_get_error(value vssl, value vretcode) {
  CAMLparam2(vssl, vretcode);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int retcode = Int_val(vretcode);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_get_error(ssl, retcode);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_read(value vssl, 
				value vbuf, value voffs, value vnum) {
  CAMLparam4(vssl, vbuf, voffs, vnum);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int buflen = Int_val(vnum);
  char* buf;
  int ret;
  if (Int_val(voffs) + buflen > caml_string_length(vbuf))
    caml_invalid_argument("Buffer too short.");
  caml_enter_blocking_section();
  buf = (char*)malloc(buflen);
  ret = SSL_read(ssl,  buf, buflen);
  caml_leave_blocking_section();
  memmove(((char*)String_val(vbuf)) + Int_val(voffs), buf, buflen);
  free(buf);
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_write(value vssl, 
				 value vbuf, value voffs, value vnum) {
  CAMLparam4(vssl, vbuf, voffs, vnum);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int buflen = Int_val(vnum);
  char* buf;
  int ret;
  if(Int_val(voffs) + buflen > caml_string_length(vbuf))
    caml_invalid_argument("Invalid offset for buffer.");
  buf = malloc(buflen);
  memmove(buf, (char*)String_val(vbuf) + Int_val(voffs), buflen);
  caml_enter_blocking_section();
  ret = SSL_write(ssl, buf, buflen);
  free(buf);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim camltls_SSL_shutdown(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_shutdown(ssl);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim camltls_SSL_get_shutdown(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal3(vres, recv, sent);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_get_shutdown(ssl);
  caml_leave_blocking_section;
  recv = Val_bool(ret & SSL_RECEIVED_SHUTDOWN);
  sent = Val_bool(ret & SSL_SENT_SHUTDOWN);
  vres = alloc_tuple(2);
  Store_field(ret, 0, recv);
  Store_field(ret, 1, sent);
  CAMLreturn(vres);
}

/*
CAMLprim camltls_SSL_set_shutdown(value vssl, value vmode) {
  CAMLparam2(vssl, vmode);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_set_shutdown(ssl);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}
*/

CAMLprim camltls_SSL_clear(value vssl) {
  CAMLparam1(vssl);
  SSL* ssl = SSL_Val(vssl);
  caml_enter_blocking_section();
  SSL_clear(ssl);
  caml_leave_blocking_section();
  CAMLreturn0;
}

CAMLprim value camltls_SSL_CTX_check_private_key(value vctx) {
  CAMLparam1(vctx);
  CAMLlocal1(vres);
  SSL_CTX* ssl_ctx = SSL_CTX_Val(vctx);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_CTX_check_private_key(ssl_ctx);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_CTX_set_default_verify_paths(value vctx) {
  CAMLparam1(vctx);
  CAMLlocal1(vres);
  SSL_CTX* ssl_ctx = SSL_CTX_Val(vctx);
  int ret;
  caml_enter_blocking_section();
  ret = SSL_CTX_set_default_verify_paths(ssl_ctx);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_SSL_get_peer_certificate(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  X509* cert;
  caml_enter_blocking_section();
  cert = SSL_get_peer_certificate(ssl);
  caml_leave_blocking_section();
  vres = alloc_small(1, Abstract_tag);
  X509_Val(vres) = cert;
  CAMLreturn(vres);
}

/* use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired */
static int verify_mode_table[] = {
  SSL_VERIFY_NONE,
  SSL_VERIFY_PEER,
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
  SSL_VERIFY_CLIENT_ONCE
};

CAMLprim value camltls_SSL_CTX_set_verify(value vctx, value vmode,
					  value vcallback) {
  CAMLparam3(vctx, vmode, vcallback);
  SSL_CTX* ssl_ctx = SSL_CTX_Val(vctx);
  int mode = convert_flag_list(vmode, verify_mode_table);
  int (*callback)(int, X509_STORE_CTX*) = 
    (int(*) (int, X509_STORE_CTX*))Field(vcallback, 0);
  caml_enter_blocking_section();
  SSL_CTX_set_verify(ssl_ctx, mode, callback);
  caml_leave_blocking_section();
  CAMLreturn0;
}

CAMLprim camltls_SSL_get_verify_result(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_Val(vssl);
  long ret;
  caml_enter_blocking_section();
  ret = SSL_get_verify_result(ssl);
  caml_leave_blocking_section();
  vres = Val_long(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_BIO_new(value unit) {
  CAMLparam0();
  CAMLlocal1(vres);
  BIO* bio;
  caml_enter_blocking_section();
  bio = BIO_new(BIO_s_mem());
  if(!bio) {
    caml_leave_blocking_section();
    mltls_error("BIO_new", "Unable to create BIO structure");
  }
  caml_leave_blocking_section();
  vres = caml_alloc_custom(&bio_ops, sizeof(BIO*), 0, 1);
  BIO_Val(vres) = bio;
  CAMLreturn(vres);
}

CAMLprim value camltls_BIO_pending(value vbio) {
  CAMLparam1(vbio);
  CAMLlocal1(vres);
  BIO* bio = BIO_Val(vbio);
  int ret;
  caml_enter_blocking_section();
  ret = BIO_pending(bio);
  caml_leave_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_BIO_write(value vbio, 
				 value vbuf, value voffs, value vlen) {
  CAMLparam4(vbio, vbuf, voffs, vlen);
  CAMLlocal1(vres);
  BIO* bio = BIO_Val(vbio);
  int buflen = Int_val(vlen);
  char* buf;
  int ret;
  if(Int_val(voffs) + buflen > caml_string_length(vbuf))
    caml_invalid_argument("Invalid offset for buffer.");
  buf = malloc(buflen);
  memmove(buf, (char*)String_val(vbuf) + Int_val(voffs), buflen);
  caml_enter_blocking_section();
  ret = BIO_write(bio, buf, buflen);
  free(buf);
  caml_enter_blocking_section();
  vres = Val_int(ret);
  CAMLreturn(vres);
}

CAMLprim value camltls_BIO_read(value vbio, 
				value vbuf, value voffs, value vlen) {
  CAMLparam4(vbio, vbuf, voffs, vlen);
  CAMLlocal1(vres);
  BIO* bio = BIO_Val(vbio);
  int buflen = Int_val(vlen);
  char* buf;
  int ret;
  if (Int_val(voffs) + buflen > caml_string_length(vbuf))
    caml_invalid_argument("Buffer too short.");
  caml_enter_blocking_section();
  buf = (char*)malloc(buflen);
  ret = BIO_read(bio, String_val(vbuf), Int_val(vlen));
  caml_enter_blocking_section();
  memmove(((char*)String_val(vbuf)) + Int_val(voffs), buf, buflen);
  free(buf);
  vres = Val_int(ret);
  CAMLreturn(vres);
}
