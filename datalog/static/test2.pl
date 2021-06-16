:- use_module(std). 
:- use_module(lifetime). 
:- use_module(name-constraints).

verified(Cert) :-
  std:isCert(Cert). 
  %lifetime:check(Cert). 
  %name-constraints:check(Cert).

