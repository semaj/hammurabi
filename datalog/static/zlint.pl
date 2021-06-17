:- use_module(std). 
:- use_module(env).
:- use_module(certs).
:- use_module(cert_0).
:- use_module(cert_1).
:- use_module(ext).
:- use_module(browser).
:- use_module(checks).

% The following functions are taken from zlint
% specifically the cabf_br tests  
% but reimplemented using Datalog 
% See www.github.com/zmap/zlint for more information 

% Checks whether or not the common 
% name is missing
caCommonNameMissing(Cert) :- 
    certs:commonName(Cert, Name),
    ext:equal(Name, ""). 

% Checks whether the country name 
% is invalid
caCountryNameInvalid(Cert) :- 
  certs:country(Cert, Country), 
  \+env:val_country(Country).

% Helper method for caCountryNameInvalid 
valCountry(Country) :- 
  env:val_country(Country).


% Checks whether or not country name 
% is missing 
caCountryNameMissing(Cert) :- 
    certs:country(Cert, Country),
    ext:equal(Country, ""). 

% Basic Constraints checks
% CA bit set
caIsCa(Cert) :-
    certs:isCA(Cert, true).

caCrlSignNotSet(Cert) :-  
    certs:keyUsageExt(Cert, true). 


% The part below is used for testing 
verified(Cert) :- 
  std:isCert(Cert), 
  \+caCountryNameMissing(Cert).
