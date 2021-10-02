:-use_module(ext).
stringMatch(Pattern, CommonName):-
    ext:s_startswith(Pattern, "*."),
    ext:s_substring(Pattern, 1, 0, P),
    ext:s_endswith(CommonName, P),
    ext:s_occurrences(Pattern, ".", N),
    ext:s_occurrences(CommonName, ".", N).
verified(Cert) :-
  std:isCert(Cert),
  stringMatch("*.google.com", "hello.google.com"). 
