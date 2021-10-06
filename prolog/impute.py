#!/usr/bin/env python3
import sys

from pyswip import Prolog
from pyswip.easy import Atom

prolog = Prolog()
prolog.consult("prolog/impute.pl")
query = sys.argv[1]

fields = [
    ("Fingerprint", '""'),
    ("SANList", '["jameslarisch.com"]'),
    ("CommonName", '""'),
    ("Lower", "1621487265"),
    ("Upper", "1621487270"),
    ("Algorithm", '"1.2.840.113549.1.1.13"'),
    ("BasicConstraints", "[]"),
    ("KeyUsage", "[]"),
    ("ExtKeyUsage", "[]"),
    ("EVStatus", "ev"),
    ("StapledResponse", "[valid, not_expired, verified, good]"),
    ("OcspResponse", "[]"),
]

probes = [
    {"Algorithm"},
    {"KeyUsage", "BasicConstraints"},
]

for missing in probes:
    input = ", ".join(
        list(map(lambda f: f[0] if f[0] in missing else f[1], fields))
    ).replace("'", "")
    solutions = prolog.query(f"{query}({input})")
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
   