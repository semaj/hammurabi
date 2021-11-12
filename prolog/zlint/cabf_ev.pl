
% EV certificates must include serialNumber in subject
evSerialNumberPresent(SerialNumber) :-
    SerialNumber \= "".


maxLifetimeEv(71003142).
% EV certificates must be 27 months in validity or less
evValidTimeNotTooLong(NotBefore, NotAfter) :-
    maxLifetimeEv(MaxDuration),
    ext:subtract(Duration, NotBefore, NotAfter),
    ext:geq(MaxDuration, Duration).

% Check that a certificate is a subscriber cert and 
% has a subject name ending in ".onion"
isOnion(Cert, San) :-
    certs:isCA(Cert, false),
    s_endswith(San, ".onion").

maxLifetimeOnion(39446190).
% certificates with .onion names can not be valid for 
% more than 15 months, maxOnionValidityMonths
onionValidTimeNotTooLong(NotBefore, NotAfter) :-
    maxLifetimeOnion(MaxDuration),
    ext:subtract(Duration, NotBefore, NotAfter),
    ext:geq(MaxDuration, Duration).
