(* openssl/demos/state_machine/state_machine.c
 *
 * Nuron, a leader in hardware encryption technology, generously
 * sponsored the development of this demo by Ben Laurie.
 *
 * See http://www.nuron.com/.
 */
 * /*
 * the aim of this demo is to provide a fully working state-machine
 * style SSL implementation, i.e. one where the main loop acquires
 * some data, then converts it from or to SSL by feeding it into the
 * SSL state machine. It then does any I/O required by the state machine
 * and loops.
 *
 * In order to keep things as simple as possible, this implementation
 * listens on a TCP socket, which it expects to get an SSL connection
 * on (for example, from s_client) and from then on writes decrypted
 * data to stdout and encrypts anything arriving on stdin. Verbose
 * commentary is written to stderr.
 *
 * This implementation acts as a server, but it can also be done for a client.  
 *)

open Mltls
open Unix
open Printf

type ssl_state_machine = {
  ctx: tls_SSL_CTX;
  rbio: tls_BIO;
  wbio: tls_BIO;
  ssl: tls_SSL
} (* SSLStateMachine *)

let ssl_state_machine_print_error err =
  eprintf "%s\n" err;
  flush Pervasives.stderr;
  let rec aux_while () =
    let l = tls_ERR_get_error () in
	    if l <> Int32.zero then
	      let str = tls_ERR_error_string l in
	        eprintf "Error %lx: %s\n" l str;
	        flush Pervasives.stderr;
	        aux_while ()
  in
    aux_while ()


let ssl_state_machine_new certificate =
  mltls_init ();
  let ctx = tls_SSL_CTX_new SSLv23_method in
  let () =
    let n = tls_SSL_CTX_use_certificate_file ctx certificate SSL_FILETYPE_PEM in
      if n <> 1 then
        ssl_state_machine_print_error "SSL_CTX_use_certificate_file";
	    assert (n > 0)
  in
  let () =
    let n = tls_SSL_CTX_use_PrivateKey_file ctx certificate SSL_FILETYPE_PEM in
      if n <> 1 then
        ssl_state_machine_print_error "SSL_CTX_use_PrivateKey_file";
	    assert (n > 0)
  in
  let () =
    let n = tls_SSL_CTX_check_private_key ctx in
	    assert (n > 0)
  in
  let () =
    let n = tls_SSL_CTX_set_default_verify_paths ctx in
	    assert (n > 0)
  in
  let () =
    let verify_callback _preverify_ok _x509_store_ctx =
	    print_endline "VERIFY CALLBACK";
	    flush Pervasives.stdout;
	    1
    in
      tls_SSL_CTX_set_verify ctx
	      [SSL_VERIFY_PEER; SSL_VERIFY_CLIENT_ONCE]
	      verify_callback
  in
  let ssl = tls_SSL_new ctx in
  let rbio = tls_BIO_new () in
  let wbio = tls_BIO_new () in
    tls_SSL_set_bio ssl rbio wbio;
    tls_SSL_set_accept_state ssl;

    { ctx = ctx;
	    ssl = ssl;
	    rbio = rbio;
	    wbio = wbio
    }

let ssl_state_machine_read_inject machine aucBuf nBuf =
  let n = tls_BIO_write machine.rbio aucBuf 0 nBuf in
    (* If it turns out this assert fails, then buffer the data here
     * and just feed it in in churn instead. Seems to me that it
     * should be guaranteed to succeed, though.
     *)
    assert(n = nBuf);
    eprintf "%d bytes of encrypted data fed to state machine\n" n;
    flush Pervasives.stderr

let ssl_state_machine_read_extract machine aucBuf nOffs nBuf =
  if not (tls_SSL_is_init_finished machine.ssl) then (
    eprintf "Doing SSL_accept\n";
    flush Pervasives.stderr;
    let n = tls_SSL_accept machine.ssl in
	    if(n = 0) then (
        eprintf "SSL_accept returned zero\n";
	      flush Pervasives.stderr;
	    );
	    if n < 0 then 
	      if tls_SSL_get_error machine.ssl n = SSL_ERROR_WANT_READ then (
          eprintf "SSL_accept wants more data\n";
	        flush Pervasives.stderr;
	      ) else (
	        ssl_state_machine_print_error "SSL_accept error";
          Pervasives.exit(7);
	      );
	    0
  ) else (
    let n = tls_SSL_read machine.ssl aucBuf nOffs nBuf in
    let n' =
	    if n < 0 then (
	      if tls_SSL_get_error machine.ssl n = SSL_ERROR_WANT_READ then (
	        eprintf "SSL_read wants more data\n";
	        flush Pervasives.stderr;
	        0
	      ) else (
	        ssl_state_machine_print_error "SSL_read error";
	        Pervasives.exit(8);
	      )
	    )
	    else
	      n
    in 
	    eprintf "%d bytes of decrypted data read from state machine\n" n';
	    flush Pervasives.stderr;
	    n'
  )

let ssl_state_machine_write_can_extract machine =
  let n = tls_BIO_pending machine.wbio in
    if n > 0 then (
	    eprintf "There is encrypted data available to write\n";
	    flush Pervasives.stderr;
    ) else (
	    eprintf "There is no encrypted data available to write\n";
	    flush Pervasives.stderr;
    );
    n <> 0

let ssl_state_machine_write_extract machine aucBuf nBuf =
  let n = tls_BIO_read machine.wbio aucBuf 0 nBuf in
    eprintf "%d bytes of encrypted data read from state machine\n" n;
    flush Pervasives.stderr;
    n

let ssl_state_machine_write_inject machine aucBuf nBuf =
  let n = tls_SSL_write machine.ssl aucBuf 0 nBuf in
    (* If it turns out this assert fails, then buffer the data here
     * and just feed it in churn instead. Seems to me that it
     * should be guaranteed to succeed, though.
     *)
    eprintf "%d bytes of unencrypted data fed to state machine: [%s]\n" 
	    n (String.sub aucBuf 0 nBuf);
    flush Pervasives.stderr;
    let err = tls_SSL_get_error machine.ssl n in
	    eprintf "SSL_write error code %s\n" 
	      (string_of_ssl_error err);
	    flush Pervasives.stderr;
	    assert (n = nBuf)
        
let openSocket port =
  let fd = socket PF_INET SOCK_STREAM 0 in
  let () = setsockopt fd SO_REUSEADDR true in

  let inet_addr = inet_addr_any in
  let sockaddr = ADDR_INET (inet_addr, port) in
	  
    Unix.bind fd sockaddr;
    Unix.listen fd 512;

    let client, _ = Unix.accept fd in
	    eprintf "Incoming accepted on port %d\n" port;
	    flush Pervasives.stderr;
	    client

exception Break

let main () =
  if Array.length Sys.argv <> 3 then (
    eprintf "%s <port> <certificate file>\n" Sys.argv.(0);
    flush Pervasives.stderr;
    Pervasives.exit 6;
  );
  
  let port = int_of_string Sys.argv.(1) in
  let certificate_file = Sys.argv.(2) in
  let fd = openSocket port in
  let machine = ssl_state_machine_new certificate_file in
    
  let rbuf = String.create 1 in
  let nrbuf = ref 0 in
    
    while true do
	    let in_fds = ref [] in
	    let out_fds = ref [] in
	    let buf = String.create 1024 in
	      (* Select socket for input *)
	      in_fds := fd :: !in_fds;
	      (* check whether there's decrypted data *)
	      if !nrbuf = 0 then
          nrbuf := ssl_state_machine_read_extract machine rbuf 0 1;
	      (* if there's decrypted data, check whether we can write it *)
	      if !nrbuf <> 0 then
	        out_fds := stdout :: !out_fds;
	      (* Select socket for output *)
	      if ssl_state_machine_write_can_extract machine then
	        out_fds := fd :: !out_fds;
	      (* Select stdin for input *)
	      in_fds := stdin :: !in_fds;
	      (* Wait for something to do something *)
	      let fd_isset = List.mem in
	      let in_fds, out_fds, _ = Unix.select !in_fds !out_fds [] (-1.0) in
	        (* Socket is ready for input *)
	        if fd_isset fd in_fds then (
            printf "Socket is ready for input\n";
            flush Pervasives.stdout;
		        let n = Unix.read fd buf 0 1024 in
		          if n = 0 then (
			          eprintf "Got EOF on socket\n";
			          flush Pervasives.stderr;
			          Pervasives.exit 0;
		          );
		          assert(n > 0);
		          ssl_state_machine_read_inject machine buf n;
	        );

	        (* stdout is ready for output (and hence we have some to 
		         send it) *)
	        if fd_isset stdout out_fds then (
		        assert (!nrbuf = 1);
		        buf.[0] <- rbuf.[0];
		        nrbuf := 0;
            
		        let n = ssl_state_machine_read_extract machine buf 1 1023 in
		          if n < 0 then (
			          ssl_state_machine_print_error "read extract failed";
			          raise Break;
		          );
		          assert(n >= 0);
		          if (n+1) > 0 then ( (* FIXME: has to be true now *)
			          let w = write stdout buf 0 (n+1) in
			            (* FIXME: we should push back any unwritten data *)
			            assert (w = (n+1));
		          )
          );
	        
	        (* Socket is ready for output (and 
		         therefore we have output to send) *)
	        if fd_isset fd out_fds then (
		        let n = ssl_state_machine_write_extract machine buf 1024 in
		          assert (n > 0);
		          
		          let w = write fd buf 0 n in
			          (* FIXME: we should push back any unwritten data *)
			          assert (w = n);
	        );
	        
	        (* Stdin is ready for input *)
	        if fd_isset stdin in_fds then (
		        let n = read stdin buf 0 1024 in
		          if n = 0 then (
			          eprintf "Got EOF on stdin\n";
			          flush Pervasives.stderr;
			          Pervasives.exit 0
		          );
		          assert(n > 0);
		          ssl_state_machine_write_inject machine buf n;
	        )
    done


let _ = main ()
