:- use_module(std). 

verified(Cert) :- 
  std:isCert(Cert), 
  \+std:caCommonNameMissing(Cert).
