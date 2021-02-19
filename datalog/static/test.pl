:- use_module(std).

verified(Cert):-
  std:isNotCA(Cert),
  certs:blah(5).
