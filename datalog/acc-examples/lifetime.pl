% Max validity period (Ballot SC22): 398 days
maxLifetime(34387200).

verified(Cert):-
  maxLifetime(MaxDuration),
  certs:notBefore(Cert, NotBeforeTime),
  certs:notAfter(Certs, NotAfterTime),
  ext:subtract(Duration, NotAfterTime, NotBeforeTime),
  ext:geq(MaxDuration, Duration).

