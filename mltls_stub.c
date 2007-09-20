#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_Val(v)             *((SSL **) &Field(v, 0))
#define SSL_CTX_Val(v)         *((SSL_CTX **) &Field(v, 0))
#define BIO_Val(v)             *((BIO **) &Field(v, 0))
#define X509_Val(v)            *((X509 **) &Field(v, 0))
#define RSA_Val(v)             *((RSA **) &Field(v, 0))

CAMLprim value camltls_ERR_get_error(value unit) {
  long ret = ERR_get_error();
  return Val_long(ret);
}

CAMLprim value camltls_ERR_error_string_n(value ve) {
  char buf[1024];
  ERR_error_string_n(Long_val(ve), buf, sizeof(buf));
  return copy_string(buf);
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

CAMLprim value camltls_SSL_CTX_new (value vmethod) {
    SSL_METHOD* method;
  SSL_CTX* ssl_ctx;
  value vres;

  switch(Int_val(vmethod)) {
  case tls_SSLv2_method:
    method = SSLv2_method();
    break;
  case tls_SSLv2_server_method:
    method = SSLv2_server_method();
    break;
  case tls_SSLv2_client_method:
    method = SSLv2_client_method();
    break;
  case tls_SSLv3_method:
    method = SSLv3_method();
    break;
  case tls_SSLv3_server_method:
    method = SSLv3_server_method();
    break;
  case tls_SSLv3_client_method:
    method = SSLv3_client_method();
    break;
  case tls_TLSv1_method:
    method = TLSv1_method();
    break;
  case tls_TLSv1_server_method:
    method = TLSv1_server_method();
    break;
  case tls_TLSv1_client_method:
    method = TLSv1_client_method();
    break;
  case tls_SSLv23_method:
    method = SSLv23_method();
    break;
  case tls_SSLv23_server_method:
    method = SSLv23_server_method();
    break;
  case tls_SSLv23_client_method:
    method = SSLv23_client_method();
    break;
  }
  ssl_ctx = SSL_CTX_new(method);

  if(ssl_ctx == NULL) 
    printf("ssl_ctx is null\n");

  vres = alloc_small(1, Abstract_tag);
  SSL_CTX_Val(vres) = ssl_ctx;
  return vres;
}

int get_file_type(value vtype) {
  switch(Int_val(vtype)) {
  case 0: return SSL_FILETYPE_PEM;
  case 1: return SSL_FILETYPE_ASN1;
  }
}

CAMLprim value camltls_SSL_CTX_use_certificate_file(value vctx, 
                                                    value vfile, value vtype) {

  int ret;
  ret = SSL_CTX_use_certificate_file(SSL_CTX_Val(vctx), 
				     String_val(vfile), 
				     get_file_type(vtype));
  return Val_int(ret);
}

// n=SSL_CTX_use_PrivateKey_file(pMachine->pCtx,szKeyFile,SSL_FILETYPE_PEM);
      
CAMLprim value camltls_SSL_CTX_use_PrivateKey_file(value vctx,
                                                   value vfile, value vtype) {
  int ret = SSL_CTX_use_PrivateKey_file(SSL_CTX_Val(vctx), 
                                        String_val(vfile), 
					get_file_type(vtype));
  return Val_int(ret);
}

CAMLprim value camltls_SSL_new(value v) {
  SSL_CTX* ssl_ctx = SSL_CTX_Val(v);
  SSL* ssl = SSL_new(ssl_ctx);
  value vres = alloc_small(1, Abstract_tag);
  SSL_Val(vres) = ssl;
  return vres;
}

CAMLprim value camltls_BIO_new(value unit) {
  BIO* bio = BIO_new(BIO_s_mem());
  value vres = alloc_small(1, Abstract_tag);
  BIO_Val(vres) = bio;
  return vres;
}

CAMLprim value camltls_SSL_set_bio(value vssl, value vrbio, value vwbio) {
  SSL_set_bio(SSL_Val(vssl), BIO_Val(vrbio), BIO_Val(vwbio));
  return Val_unit;
}

CAMLprim value camltls_SSL_set_accept_state(value vssl) {
  SSL_set_accept_state(SSL_Val(vssl));
  return Val_unit;
}

CAMLprim value camltls_SSL_is_init_finished(value vssl) {
  int ret = SSL_is_init_finished(SSL_Val(vssl));
  return Val_bool(ret);
}

CAMLprim value camltls_SSL_accept(value vssl) {
  int ret = SSL_accept(SSL_Val(vssl));
  return Val_int(ret);
}

CAMLprim value camltls_SSL_get_error(value vssl, value vret) {
  int res = SSL_get_error(SSL_Val(vssl), Int_val(vret));
  return Val_int(res);
}

/* SSL_library_init() always returns "1", so it is safe to discard the
   return value. 
*/
CAMLprim value camltls_SSL_library_init(value unit) {
  SSL_library_init();
  return Val_unit;
}

CAMLprim value camltls_OpenSSL_add_ssl_algorithms(value unit) {
  OpenSSL_add_ssl_algorithms();
  return Val_unit;
}

CAMLprim value camltls_SSL_load_error_strings(value unit) {
  SSL_load_error_strings();
  return Val_unit;
}

CAMLprim value camltls_ERR_load_crypto_strings(value unit) {
  ERR_load_crypto_strings();
  return Val_unit;
}

CAMLprim value camltls_SSL_read(value vssl, 
				value vbuf, value voffs, value vnum) {
  int ret = SSL_read(SSL_Val(vssl), 
		     &Byte_u(vbuf, Int_val(voffs)), Int_val(vnum));
  return Val_int(ret);
}

CAMLprim value camltls_SSL_write(value vssl, 
				 value vbuf, value voffs, value vnum) {
  int ret = SSL_write(SSL_Val(vssl), 
		      &Byte_u(vbuf, Int_val(voffs)), Int_val(vnum));
  return Val_int(ret);
}

CAMLprim value camltls_BIO_pending(value vbio) {
  int ret = BIO_pending(BIO_Val(vbio));
  return Val_int(ret);
}

CAMLprim value camltls_BIO_write(value vbio, value vbuf, value vlen) {
  int ret = BIO_write(BIO_Val(vbio), String_val(vbuf), Int_val(vlen));
  return Val_int(ret);
}

CAMLprim value camltls_BIO_read(value vbio, value vbuf, value vlen) {
  int ret = BIO_read(BIO_Val(vbio), String_val(vbuf), Int_val(vlen));
  return Val_int(ret);
}

CAMLprim value camltls_SSL_CTX_check_private_key(value vctx) {
  int ret = SSL_CTX_check_private_key(SSL_CTX_Val(vctx));
  return Val_int(ret);
}

CAMLprim value camltls_SSL_CTX_set_default_verify_paths(value vctx) {
  int ret = SSL_CTX_set_default_verify_paths(SSL_CTX_Val(vctx));
  return Val_int(ret);
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
  int mode = convert_flag_list(vmode, verify_mode_table);
  int (*callback)(int, X509_STORE_CTX*) = 
    (int(*) (int, X509_STORE_CTX*))Field(vcallback, 0);
  SSL_CTX_set_verify(SSL_CTX_Val(vctx), mode, callback);
  return Val_unit;
}

CAMLprim camltls_SSL_get_verify_result(value vssl) {
  long ret = SSL_get_verify_result(SSL_Val(vssl));
  return Val_long(ret);
}
