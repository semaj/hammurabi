import sys
from pyswip import Prolog
from pyswip.easy import Atom

prolog = Prolog()
prolog.consult("examples.pl")
query = sys.argv[1]

fields = [
    ("Fingerprint", '""'),
    ("SANList", '["www.bing.com"]'),
    ("Subject", '""'),
    ("Lower", '1617423689'),
    ("Upper", '1618387690'),
    ("Algorithm", '"1.2.840.10040.4.3"'),
    ("BasicConstraints", '[]'),
    ("KeyUsage", '[]'),
    ("ExtKeyUsage", '[]'),
    ("CertPolicies", '["1.3.6.1.4.1.6334.1.100.1", 0]'),
    ("StapledResponse", '[verified, not_expired, valid]'),
    ("OcspResponse", '[verified, not_expired, valid, good]'),
    ("RootSubject", '["Cybertrust Global Root", "", "", "", "Cybertrust, Inc"]'),
    ("RootFingerprint", '"5A2FC03F0C83B090BBFA40604B0988446C7636183DF9846E17101A447FB8EFD6"'),
    ("RootLower", '631170000'),
    ("RootUpper", '1618287689'),
    ("RootBasicConstraints", '[ca, 10]'),
    ("RootKeyUsage", '[]')
]

probes = [
    {"SANList", "Subject"},
    {"Algorithm"},
    {"KeyUsage"},
    {"BasicConstraints"},
    {"ExtKeyUsage"},
    {"BasicConstraints", "KeyUsage", "ExtKeyUsage"},
    {"StapledResponse", "OcspResponse"},
    # {"RootBasicConstraints", "RootKeyUsage"}
]

for missing in probes:
    input = ", ".join(list(map(lambda f: f[0] if f[0] in missing else f[1], fields))).replace("'", "")
    solutions = prolog.query(f"{query}({input})")
    seen = set()
    for sol in solutions:
        for m in missing:
            if type(sol[m]) == bytes:
                sol[m] = sol[m].decode()
            if type(sol[m]) == Atom:
                sol[m] = sol[m].value
            if m in ("KeyUsage", "ExtKeyUsage"):
                sol[m] = set(s.value for s in sol[m])
            if type(sol[m]) == list:
                sol[m] = [s.value if hasattr(s, "value") else s.decode() for s in sol[m]]

        key = "".join([str(sol[m]) for m in sol])
        if key not in seen:
            for m in missing:
                print(f"{m} {sol[m]}")
            seen.add(key)
            print("--")
    print("\n---------------------\n")
    