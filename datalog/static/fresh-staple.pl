% TODO: Pass stapled OCSP response
stapledOcsp(cert1, true, true, false, ok).

sixMonths(15780000). % Six months in seconds

certIsFresh(Cert):-
  % Get current UNIX timestamp
  currentTime(T), sixMonths(D),
  notBefore(Cert, NotBeforeTime),
  % Age =< six months
  subtract(Age, T, NotBeforeTim), geq(D, Age).

verified(Cert):-
  % Cert must be less than six months old
  certIsFresh(Cert).

% Or a valid stapled OCSP response must be received
verified(Cert):-
  stapled_ocsp_response(Cert),
  stapledOcsp(Cert, true, true, false, ok).

