
% EV certificates must include serialNumber in subject
evSerialNumberPresent(SerialNumber) :-
    SerialNumber \= "".

% EV certificates must be 27 months in validity or less



% certificates with .onion names can not be valid for 
% more than %d months, maxOnionValidityMonths
