import eqfunc
import r2pipe


r2 = r2pipe.open('examples/binteste')
equals = eqfunc.find_equals('sym._func', r2, False)
print(equals)