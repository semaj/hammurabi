# The following code is a python driver that 
# can query a singlular lint rule (pass/fail) and a singular 
# applies rule (NA) from a specific prolog file 
# Usage: python3 driver.py [Prolog File] [Lint Rule] [Applies Rule]

from pyswip import Prolog 
import sys
prolog = Prolog()
prolog.consult(sys.argv[1])

def isEmpty(s): 
    for i in s: 
        return False 
    return True

applies = True
if (len(sys.argv) > 3): 
    #app_query = prolog.query(sys.argv[3] + "(X)")
    applies = not isEmpty(prolog.query(sys.argv[3] + "(X)"))
    if not applies: 
        print("NA")
if applies: 
    soln = prolog.query(sys.argv[2] + "(X)")
    if not isEmpty(soln): 
        print("pass")
    else: 
        print("fail")
