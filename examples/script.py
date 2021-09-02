import eqfunc
import r2pipe


r2 = r2pipe.open('examples/binteste')
equals = eqfunc.find_equals('0x1167', r2, False)
print(equals)
