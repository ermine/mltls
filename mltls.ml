type tls_SSL
type tls_SSL_CTX
type tls_BIO
type tls_X509
type tls_X509_STORE_CTX

external tls_ERR_get_error: unit -> int32
   = "camltls_ERR_get_error"

external tls_ERR_error_string_n: int32 -> string
   = "camltls_ERR_error_string_n"


type tls_method =
   | SSLv2_method
   | SSLv2_server_method
   | SSLv2_client_method
   | SSLv3_method
   | SSLv3_server_method
   | SSLv3_client_method
   | TLSv1_method
   | TLSv1_server_method
   | TLSv1_client_method
   | SSLv23_method 
   | SSLv23_server_method
   | SSLv23_client_method

external tls_SSL_CTX_new: tls_method -> tls_SSL_CTX
   = "camltls_SSL_CTX_new"

type certificate_file_type =
   | SSL_FILETYPE_PEM
   | SSL_FILETYPE_ASN1

external tls_SSL_CTX_use_certificate_file: tls_SSL_CTX -> string -> 
   certificate_file_type -> int
   = "camltls_SSL_CTX_use_certificate_file"

external tls_SSL_CTX_use_PrivateKey_file: tls_SSL_CTX -> string -> 
   certificate_file_type -> int
   = "camltls_SSL_CTX_use_PrivateKey_file"

external tls_SSL_new: tls_SSL_CTX -> tls_SSL
   = "camltls_SSL_new"

 external tls_BIO_new: unit -> tls_BIO
   = "camltls_BIO_new"

external tls_SSL_set_bio: tls_SSL -> tls_BIO -> tls_BIO -> unit
   = "camltls_SSL_set_bio"

external tls_SSL_set_accept_state: tls_SSL -> unit
   = "camltls_SSL_set_accept_state"

external tls_BIO_write: tls_BIO -> string -> int -> int
   = "camltls_BIO_write"

external tls_SSL_is_init_finished: tls_SSL -> bool
   = "camltls_SSL_is_init_finished"

external tls_SSL_accept: tls_SSL -> int
   = "camltls_SSL_accept"


type ssl_error =
   | SSL_ERROR_NONE
   | SSL_ERROR_SSL
   | SSL_ERROR_WANT_READ
   | SSL_ERROR_WANT_WRITE
   | SSL_ERROR_WANT_X509_LOOKUP
   | SSL_ERROR_SYSCALL           (* look at error stack/return value/errno *)
   | SSL_ERROR_ZERO_RETURN
   | SSL_ERROR_WANT_CONNECT
   | SSL_ERROR_WANT_ACCEPT

let string_of_ssl_error = function
   | SSL_ERROR_NONE -> "SSL_ERROR_NONE"
   | SSL_ERROR_SSL -> "SSL_ERROR_SSL"
   | SSL_ERROR_WANT_READ -> "SSL_ERROR_WANT_READ"
   | SSL_ERROR_WANT_WRITE -> "SSL_ERROR_WANT_WRITE"
   | SSL_ERROR_WANT_X509_LOOKUP -> "SSL_ERROR_WANT_X509_LOOKUP"
   | SSL_ERROR_SYSCALL ->           (* look at error stack/return value/errno *)
	 "SSL_ERROR_SYSCALL"
   | SSL_ERROR_ZERO_RETURN -> "SSL_ERROR_ZERO_RETURN"
   | SSL_ERROR_WANT_CONNECT -> "SSL_ERROR_WANT_CONNECT"
   | SSL_ERROR_WANT_ACCEPT -> "SSL_ERROR_WANT_ACCEPT"

external tls_SSL_get_error: tls_SSL -> int -> ssl_error
   = "camltls_SSL_get_error"

external tls_SSL_library_init: unit -> unit
   = "camltls_SSL_library_init"

external tls_OpenSSL_add_ssl_algorithms: unit -> unit
   = "camltls_OpenSSL_add_ssl_algorithms"

external tls_SSL_load_error_strings: unit -> unit
   = "camltls_SSL_load_error_strings"

external tls_ERR_load_crypto_strings: unit -> unit
   = "camltls_ERR_load_crypto_strings"

external tls_SSL_read: tls_SSL -> string -> int -> int -> int
   = "camltls_SSL_read"

external tls_SSL_write: tls_SSL -> string -> int -> int -> int
   = "camltls_SSL_write"

external tls_BIO_pending: tls_BIO -> int
   = "camltls_BIO_pending"

external tls_BIO_read: tls_BIO -> string -> int -> int
   = "camltls_BIO_read"

external tls_BIO_write: tls_BIO -> string -> int -> int
   = "camltls_BIO_write"

external  tls_SSL_CTX_check_private_key: tls_SSL_CTX -> int
   = "camltls_SSL_CTX_check_private_key"

external tls_SSL_CTX_set_default_verify_paths: tls_SSL_CTX -> int
   = "camltls_SSL_CTX_set_default_verify_paths"

type set_verify_mode =
   | SSL_VERIFY_NONE
   | SSL_VERIFY_PEER
   | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
   | SSL_VERIFY_CLIENT_ONCE

type verify_callback = int -> tls_X509_STORE_CTX -> int

external tls_SSL_CTX_set_verify: tls_SSL_CTX -> set_verify_mode list ->
   verify_callback -> unit
   = "camltls_SSL_CTX_set_verify"

external tls_SSL_get_verify_result: tls_SSL -> int
   = "camltls_SSL_get_verify_result"
