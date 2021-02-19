:- use_module(std).

verified(Cert):-
  std:isNotCA(Cert).
