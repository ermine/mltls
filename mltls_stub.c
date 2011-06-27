/*
 * (c) 2007-2010 Anastasia Gornostaeva <ermine@ermine.pp.ru>
 */

#include <caml/alloc.h>
#include <caml/mlvalues.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/custom.h>
#include <caml/signals.h>
#include <caml/callback.h>

#include "wrapper.h"

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_val(v)             (*((SSL **) Data_custom_val(v)))
#define SSL_CTX_val(v)         (*((SSL_CTX**)Data_custom_val(v)))
#define BIO_val(v)             (*((BIO **) Data_custom_val(v)))

#define X509_val(v)            (*((X509 **) &Field(v, 0)))
#define RSA_val(v)             (*((RSA **) &Field(v, 0)))

#define X509_STORE_CTX_val(v)  (*((X509_STORE_CTX **) &Field(v, 0)))

static void finalize_ssl(value block) {
  SSL* ssl = SSL_val(block);
  SSL_free(ssl);
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
  SSL_CTX* ssl_ctx = SSL_CTX_val(block);
  SSL_CTX_free(ssl_ctx);
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
  BIO* bio = BIO_val(block);
  BIO_free(bio);
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
CAMLprim value ml_init(value unit) {
  SSL_library_init();
  OpenSSL_add_ssl_algorithms();
  ERR_load_crypto_strings();
  SSL_load_error_strings();

  mltls_error_exn = caml_named_value("Mltls_Error");
  if (mltls_error_exn == NULL)
    caml_invalid_argument("Exception Mltls_Error is not initialized");

  return Val_unit;
}

static void mltls_error(char* fn, char* msg) {
  CAMLparam0();
  CAMLlocalN(vargs, 2);
  if (mltls_error_exn == NULL)
    caml_invalid_argument("Exception Mltls_Error is not initialized");
  if (msg == NULL)
    msg = "";
  vargs[0] = caml_copy_string(fn);
  vargs[1] = caml_copy_string(msg);
  caml_raise_with_args(*mltls_error_exn, 2, vargs);
  CAMLreturn0;
}

CAMLprim value ml_ERR_load_crypto_strings(value unit) {
  ERR_load_crypto_strings();
  return(Val_unit);
}

CAMLprim value ml_ERR_get_error(value unit) {
  CAMLparam1(unit);
  CAMLreturn(caml_copy_int32(ERR_get_error()));
}

CAMLprim value ml_ERR_error_string(value ve) {
  CAMLparam1(ve);
  char* err = ERR_error_string(Unsigned_long_val(ve), NULL);
  CAMLreturn(caml_copy_string(err));
}

CAMLprim value ml_ERR_error_string_n(value ve) {
  CAMLparam1(ve);
  char err[200];
  ERR_error_string_n(Unsigned_long_val(ve), err, sizeof(err));
  CAMLreturn(caml_copy_string(err));
}

CAMLprim value ml_ERR_lib_error_string(value ve) {
  CAMLparam1(ve);
  CAMLlocal1(vres);
  const char* err = ERR_lib_error_string(Unsigned_long_val(ve));
  if(err == NULL)
    vres = caml_copy_string("");
  else
    vres = caml_copy_string(err);
  CAMLreturn(vres);
}

CAMLprim value ml_ERR_func_error_string(value ve) {
  CAMLparam1(ve);
  CAMLlocal1(vres);
  const char* err = ERR_func_error_string(Unsigned_long_val(ve));
  if(err == NULL)
    vres = caml_copy_string("");
  else
    vres = caml_copy_string(err);
  CAMLreturn(vres);
}

CAMLprim value ml_ERR_reason_error_string(value ve) {
  CAMLparam1(ve);
  CAMLlocal1(vres);
  const char* err = ERR_reason_error_string(Unsigned_long_val(ve));
  if(err == NULL)
    vres = caml_copy_string("");
  else
    vres = caml_copy_string(err);
  CAMLreturn(vres);
}

#define tls_SSLv3_method           0
#define tls_SSLv3_server_method    1
#define tls_SSLv3_client_method    2
#define tls_TLSv1_method           3
#define tls_TLSv1_server_method    4
#define tls_TLSv1_client_method    5
#define tls_SSLv23_method          6
#define tls_SSLv23_server_method   7
#define tls_SSLv23_client_method   8

static const SSL_METHOD* get_method(int method) {
  switch(method) {
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

CAMLprim value ml_SSL_CTX_new(value vmethod) {
  CAMLparam1(vmethod);
  CAMLlocal1(vres);
  SSL_CTX* ssl_ctx = SSL_CTX_new(get_method(Int_val(vmethod)));
  if(ssl_ctx == NULL) {
    mltls_error("SSL_CTX_new", "Unable to create SSL_CTX structure");
  }
  vres = caml_alloc_custom(&ssl_ctx_ops, sizeof(SSL_CTX*), 0, 1);
  SSL_CTX_val(vres) = ssl_ctx;
  CAMLreturn(vres);
}

static int get_file_type(int type) {
  switch(type) {
  case 0: return SSL_FILETYPE_PEM;
  case 1: return SSL_FILETYPE_ASN1;
  default: caml_invalid_argument("Unknown file type");
  }
}

CAMLprim value ml_SSL_CTX_use_certificate_file(value vctx, 
                                                    value vfile, value vtype) {
  int ret = SSL_CTX_use_certificate_file(SSL_CTX_val(vctx),
                                         String_val(vfile), 
                                         get_file_type(Int_val(vtype)));
  return Val_int(ret);
}

CAMLprim value ml_SSL_CTX_use_PrivateKey_file(value vctx,
                                                   value vfile, value vtype) {
  int ret = SSL_CTX_use_PrivateKey_file(SSL_CTX_val(vctx),
                                        String_val(vfile),
                                        get_file_type(Int_val(vtype)));
  return Val_int(ret);
}

CAMLprim value ml_SSL_new(value vctx) {
  CAMLparam1(vctx);
  CAMLlocal1(vres);
  SSL* ssl = SSL_new(SSL_CTX_val(vctx));
  if(ssl == NULL) {
    mltls_error("SSL_new", "Unable to create SSL structure");
  }
  vres = caml_alloc_custom(&ssl_ops, sizeof(SSL*), 0, 1);
  SSL_val(vres) = ssl;
  CAMLreturn(vres);
}

ML_1(SSL_set_accept_state, SSL_val, Unit)
ML_1(SSL_set_connect_state, SSL_val, Unit)
ML_1(SSL_is_init_finished, SSL_val, Val_bool)

ML_2(SSL_set_fd, SSL_val, Int_val, Val_int)
ML_2(SSL_set_rfd, SSL_val, Int_val, Val_int)
ML_2(SSL_set_wfd, SSL_val, Int_val, Val_int)

CAMLprim value ml_SSL_accept(value vssl) {
  int ret;

  caml_enter_blocking_section();
  ret = SSL_accept(SSL_val(vssl));
  caml_leave_blocking_section();
  return Val_int(ret);
}

CAMLprim value ml_SSL_connect(value vssl) {
  int ret;

  caml_enter_blocking_section();
  ret = SSL_connect(SSL_val(vssl));
  caml_leave_blocking_section();
  return Val_int(ret);
}

CAMLprim value ml_SSL_do_handshake(value vssl) {
  int ret;

  caml_enter_blocking_section();
  ret = SSL_do_handshake(SSL_val(vssl));
  caml_leave_blocking_section();
  return Val_int(ret);
}

ML_2(SSL_get_error, SSL_val, Int_val, Val_int)

CAMLprim value ml_SSL_read(value vssl, 
                           value vbuf, value voffs, value vnum) {
  CAMLparam4(vssl, vbuf, voffs, vnum);
  long offs = Long_val(voffs);
  long len = Long_val(vnum);
  char* tmpbuf;
  int ret;
  if(offs + len > caml_string_length(vbuf))
    caml_invalid_argument("Buffer too short");
  tmpbuf = (char*) caml_stat_alloc(len);
  caml_enter_blocking_section();
  ret = SSL_read(SSL_val(vssl), tmpbuf, len);
  caml_leave_blocking_section();
  memcpy(&Byte(vbuf, offs), tmpbuf, ret);
  caml_stat_free(tmpbuf);
  CAMLreturn(Val_int(ret));
}

CAMLprim value ml_SSL_write(value vssl, 
                                 value vbuf, value voffs, value vnum) {
  CAMLparam4(vssl, vbuf, voffs, vnum);
  long offs = Long_val(voffs);
  long len = Long_val(vnum);
  char* tmpbuf;
  int ret;
  if(offs + len > caml_string_length(vbuf))
    caml_invalid_argument("Invalid offset for buffer");
  tmpbuf = (char*) caml_stat_alloc(len);
  memcpy(tmpbuf, &Byte(vbuf, offs), len);
  caml_enter_blocking_section();
  ret = SSL_write(SSL_val(vssl), tmpbuf, len);
  caml_leave_blocking_section();
  caml_stat_free(tmpbuf);
  CAMLreturn(Val_int(ret));
}

ML_1(SSL_shutdown, SSL_val, Val_int)

CAMLprim value ml_SSL_get_shutdown(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal3(vres, recv, sent);
  SSL* ssl = SSL_val(vssl);
  int ret;
  ret = SSL_get_shutdown(ssl);
  recv = Val_bool(ret & SSL_RECEIVED_SHUTDOWN);
  sent = Val_bool(ret & SSL_SENT_SHUTDOWN);
  vres = caml_alloc_tuple(2);
  Store_field(vres, 0, recv);
  Store_field(vres, 1, sent);
  CAMLreturn(vres);
}

/*
CAMLprim value ml_SSL_set_shutdown(value vssl, value vmode) {
  CAMLparam2(vssl, vmode);
  CAMLlocal1(vres);
  SSL* ssl = SSL_val(vssl);
  int ret;
  ret = SSL_set_shutdown(ssl);
  vres = Val_int(ret);
  CAMLreturn(vres);
}
*/

ML_1(SSL_clear, SSL_val, Unit)
ML_1(SSL_CTX_check_private_key, SSL_CTX_val, Val_int)
ML_1(SSL_CTX_set_default_verify_paths, SSL_CTX_val, Val_int)

/* ML_1(SSL_get_perr_certificate, SSL_val, alloc_X509) */
CAMLprim value ml_SSL_get_peer_certificate(value vssl) {
  CAMLparam1(vssl);
  CAMLlocal1(vres);
  SSL* ssl = SSL_val(vssl);
  X509* cert;
  cert = SSL_get_peer_certificate(ssl);
  vres = caml_alloc_small(1, Abstract_tag);
  X509_val(vres) = cert;
  CAMLreturn(vres);
}

/* use either SSL_VERIFY_NONE or SSL_VERIFY_PEER, the last 2 options
 * are 'ored' with SSL_VERIFY_PEER if they are desired */
static int tbl_verify_mode[] = {
  SSL_VERIFY_NONE,
  SSL_VERIFY_PEER,
  SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
  SSL_VERIFY_CLIENT_ONCE
};

CAMLprim value ml_SSL_CTX_set_verify(value vctx, value vmode,
                                          value vcallback) {
  CAMLparam3(vctx, vmode, vcallback);
  int mode = caml_convert_flag_list(vmode, tbl_verify_mode);
  int (*callback_verify)(int, X509_STORE_CTX*) = NULL;

  if(Is_block(vcallback))
    callback_verify = (int(*) (int, X509_STORE_CTX*))Field(vcallback, 0);
  caml_enter_blocking_section();
  SSL_CTX_set_verify(SSL_CTX_val(vctx), mode, callback_verify);
  caml_leave_blocking_section();
  CAMLreturn(Val_unit);
}

ML_1(SSL_get_verify_result, SSL_val, Val_long)

CAMLprim value ml_BIO_new(value unit) {
  CAMLparam0();
  CAMLlocal1(vres);
  BIO* bio = BIO_new(BIO_s_mem());
  if(!bio) {
    mltls_error("BIO_new", "Unable to create BIO structure");
  }
  vres = caml_alloc_custom(&bio_ops, sizeof(BIO*), 0, 1);
  BIO_val(vres) = bio;
  CAMLreturn(vres);
}

ML_3(SSL_set_bio, SSL_val, BIO_val, BIO_val, Unit)
ML_1(BIO_pending, BIO_val, Val_int)

CAMLprim value ml_BIO_write(value vbio, 
                                 value vbuf, value voffs, value vlen) {
  CAMLparam4(vbio, vbuf, voffs, vlen);
  long offs = Long_val(voffs);
  long len = Long_val(vlen);
  char* tmpbuf;
  int ret;

  if(offs + len  > caml_string_length(vbuf))
    caml_invalid_argument("Invalid offset for buffer");
  tmpbuf = (char*) caml_stat_alloc(len);
  memcpy(tmpbuf, &Byte(vbuf, offs), len);
  caml_enter_blocking_section();
  ret = BIO_write(BIO_val(vbio), tmpbuf, len);
  caml_leave_blocking_section();
  caml_stat_free(tmpbuf);
  CAMLreturn(Val_int(ret));
}

CAMLprim value ml_BIO_read(value vbio, 
                           value vbuf, value voffs, value vlen) {
  CAMLparam4(vbio, vbuf, voffs, vlen);
  long len = Int_val(vlen);
  long offs = Long_val(voffs);
  char* tmpbuf;
  int ret;

  if (offs + len > caml_string_length(vbuf))
    caml_invalid_argument("Buffer too short");
  tmpbuf = (char*) caml_stat_alloc(len);
  caml_enter_blocking_section();
  ret = BIO_read(BIO_val(vbio), tmpbuf, len);
  caml_leave_blocking_section();
  memcpy(&Byte(vbuf, offs), tmpbuf, ret);;
  caml_stat_free(tmpbuf);
  CAMLreturn(Val_int(ret));
}
