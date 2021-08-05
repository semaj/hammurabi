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
    app_query = prolog.query(sys.argv[3] + "(X)")
    applies = not isEmpty(app_query)
    if not applies: 
        print("NA")
if applies: 
    soln = prolog.query(sys.argv[2] + "(X)")
    if not isEmpty(soln): 
        print("Pass")
    else: 
        print("Fail")

def isEmpty(s): 
    for i in s: 
        return False 
    return True