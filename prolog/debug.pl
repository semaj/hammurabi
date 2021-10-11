#!/usr/bin/env swipl

:- initialization(main, after_load).


main([Client]):-
  % consult the certs.pl file
  consult("prolog/job/certs"),
  % consult the {client}.pl file
  string_concat("prolog/static/", Client, ClientSrc),
  consult(ClientSrc),
  % don't stop at any tracepoints
  leash(-all),
  % only show failures
  visible(-all),
  visible(+fail),
  visible(+exit),
  % enable trace
  trace,
  % attempt chain verification
  Client:certVerifiedChain(cert_0).
  
