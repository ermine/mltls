(*
 * (c) 2006-2010 Anastasia Gornostaeva <ermine@ermine.pp.ru>
 *)

exception Error of string * string

type tls_SSL
type tls_SSL_CTX
type tls_BIO
type tls_X509
type tls_X509_STORE_CTX

external tls_ERR_load_crypto_strings: unit -> unit
  = "ml_ERR_load_crypto_strings"

external tls_ERR_get_error : unit -> int32
  = "ml_ERR_get_error"
external tls_ERR_error_string : int32 -> string
  = "ml_ERR_error_string"
external tls_ERR_error_string_n : int32 -> string
  = "ml_ERR_error_string_n"
external tls_ERR_lib_error_string : int32 -> string
  = "ml_ERR_lib_error_string"
external tls_ERR_func_error_string : int32 -> string
  = "ml_ERR_func_error_string"
external tls_ERR_reason_error_string : int32 -> string
  = "ml_ERR_reason_error_string"

type tls_method =
(*
  (* SSLv2 is insecure and openssl since 1.0.0 disables this method by default *)
  | SSLv2_method
  | SSLv2_server_method
  | SSLv2_client_method
*)
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
  = "ml_SSL_CTX_new"

type certificate_file_type =
  | SSL_FILETYPE_PEM
  | SSL_FILETYPE_ASN1
      
external tls_SSL_CTX_use_certificate_file: tls_SSL_CTX -> string -> 
  certificate_file_type -> int
  = "ml_SSL_CTX_use_certificate_file"

external tls_SSL_CTX_use_PrivateKey_file: tls_SSL_CTX -> string -> 
  certificate_file_type -> int
  = "ml_SSL_CTX_use_PrivateKey_file"

external tls_SSL_new: tls_SSL_CTX -> tls_SSL
  = "ml_SSL_new"

external tls_SSL_set_fd: tls_SSL -> Unix.file_descr -> int
  = "ml_SSL_set_fd"

external tls_SSL_set_rfd: tls_SSL -> Unix.file_descr -> int
  = "ml_SSL_set_rfd"

external tls_SSL_set_wfd: tls_SSL -> Unix.file_descr -> int
  = "ml_SSL_set_wfd"

external tls_SSL_set_bio: tls_SSL -> tls_BIO -> tls_BIO -> unit
  = "ml_SSL_set_bio"

external tls_SSL_set_accept_state: tls_SSL -> unit
  = "ml_SSL_set_accept_state"

external tls_SSL_set_connect_state: tls_SSL -> unit
  = "ml_SSL_set_connect_state"

external tls_SSL_is_init_finished: tls_SSL -> bool
  = "ml_SSL_is_init_finished"

external tls_SSL_accept: tls_SSL -> int
  = "ml_SSL_accept"

external tls_SSL_connect: tls_SSL -> int
  = "ml_SSL_connect"

external tls_SSL_do_handshake: tls_SSL -> int
  = "ml_SSL_do_handshake"

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
  = "ml_SSL_get_error"

external tls_SSL_read: tls_SSL -> string -> int -> int -> int
  = "ml_SSL_read"

external tls_SSL_write: tls_SSL -> string -> int -> int -> int
  = "ml_SSL_write"

external tls_SSL_shutdown: tls_SSL -> int
  = "ml_SSL_shutdown"

external tls_SSL_get_shutdown: tls_SSL -> bool * bool
  = "ml_SSL_get_shutdown"

(*
  external tls_SSL_set_shutdown: tls_SSL ->
  = "ml_SSL_set_shutdown"
*)

external tls_SSL_clear: tls_SSL -> int
  = "ml_SSL_clear"

external  tls_SSL_CTX_check_private_key: tls_SSL_CTX -> int
  = "ml_SSL_CTX_check_private_key"

external tls_SSL_CTX_set_default_verify_paths: tls_SSL_CTX -> int
  = "ml_SSL_CTX_set_default_verify_paths"

external tls_SSL_get_peer_certificate: tls_SSL -> tls_X509
  = "ml_SSL_get_peer_certificate"

type verify_mode =
  | SSL_VERIFY_NONE
  | SSL_VERIFY_PEER
  | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
  | SSL_VERIFY_CLIENT_ONCE

type verify_callback = int -> tls_X509_STORE_CTX -> int

external tls_SSL_CTX_set_verify: tls_SSL_CTX -> verify_mode list ->
  verify_callback -> unit
  = "ml_SSL_CTX_set_verify"

external tls_SSL_get_verify_result: tls_SSL -> int
  = "ml_SSL_get_verify_result"

external tls_BIO_new : unit -> tls_BIO
  = "ml_BIO_new"

external tls_BIO_pending : tls_BIO -> int 
  = "ml_BIO_pending"

external tls_BIO_read : tls_BIO -> string -> int -> int -> int
  = "ml_BIO_read"

external tls_BIO_write : tls_BIO -> string -> int -> int -> int
  = "ml_BIO_write"

external tls_init: unit -> unit
  = "ml_init"

let _ =
  Callback.register_exception "Mltls_Error" (Error ("", ""))
