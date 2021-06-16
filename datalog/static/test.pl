:- use_module(std).

verified(Cert) :-
  std:isCert(Cert).
  %certs:san(Cert, Name), 
  %split_string(Name, ".", "", L),
  %last(End, L),
  %End =\= "com".

