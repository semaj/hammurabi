sixMonths(15780000). % Six months in seconds

certIsFresh(Cert):-
  ext:now(T),
  sixMonths(D),
  certs:notBefore(Cert, NotBeforeTime),
  % Age =< six months
  ext:subtract(Age, T, NotBeforeTime),
  ext:geq(D, Age).

verified(Cert):-
  % Cert must be less than six months old
  certIsFresh(Cert).

% Or a valid stapled OCSP response must be received
verified(Cert):-
  certs:stapledOcspPresent(Cert, true),
  certs:stapledOcspValid(Cert, true),
  certs:stapledOcspVerified(Cert, true),
  certs:stapledOcspExpired(Cert, false),
  certs:stapledOcspStatus(Cert, good).

