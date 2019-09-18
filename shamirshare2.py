###############################################################################
# SHAMIRSHARE2.py
# Simplified implementation of the Shamir Secret Sharing mechanism over 8-bit,
# 16-bit, and prime fields as specified in the KMIP v2.0 protocol.
# Operator overloading is not used, neither is type coercion outside
# of __init__()
# Author: Robert Campbell, <r.campbel.256@gmail.com>
# Date: 18 Sept 2019
# Version 0.1
# License: Simplified BSD (see details at bottom)
###############################################################################

"""Code to perform a Shamir Secret Sharing split of a secret, as in KMIP v2.0.
Possible ground fields include:
    GF(2^8) - GF8, as specified by AES block cipher
    GF(2^16) - GF16, a quadratic extension of GF8
    GF(p) - GFp, for a specified prime p
Usage:  Implement a 3-of-5 KeySplit over GF(101)
        >>> from shamirshare import *
        >>> gf101 = GFp(101)                 # Create the field GF(101)
        ################### Create a new key/secret and split it
        # Choose three random splits: 1-->35, 2-->92, 3-->11
        >>> pfit = fit(((1,35),(2,92),(3,11)),gf101); [pfit[i].value for i in range(3)]
            [42, 62. 32]
        # So poly is (42 + 62*x + 32*x^2), and secret is pfit(0) = 42 (Life, the Universe, ...)
        # Now generate two more splits for users 4 and 5
        >>> [eval(pfit,i).value for i in range(4,6)]
            [95, 41]
        # So the splits are:  1-->35, 2-->92, 3-->11, 4-->95, 5-->41
        ################### Now recover the secret using splits for users 1, 4 and 5
        >>> pfit2 = fit(((1,35),(4,95),(5,41)),gf101); [pfit2[i].value for i in range(3)]
            [42, 62. 32]
        >>> eval(pfit2,0).value
            42
"""

__version__ = '0.1'  # Format specified in Python PEP 396
Version = 'shamirshare2.py, version ' + __version__ + ', 18 Sept, 2019, by Robert Campbell, <r.campbel.256@gmail.com>'

import sys     # Check Python2 or Python3

################# Code allowing Python 2 or 3 ################################
def isStrType(x):
    if sys.version_info < (3,): return isinstance(x, (basestring,))
    else: return isinstance(x, (str,))

def isIntType(x):
    if sys.version_info < (3,): return isinstance(x, (int, long,))
    else: return isinstance(x, (int,))

def isListType(x):    # List or Tuple: [1,2] or (1,2)
    return isinstance(x, (list, tuple,))


############################# Class GFp #################################
# Class GFp
# A singleton class implementing the finite field GF(p), where p is a
#   specified prime integer.

class GFp(object):
    """A prime field, given some specified prime p
    Usage:
        >>> from shamirshare import *
        >>> gf250 = GFp(1125899906842679)  # First prime larger than 2^50
        >>> a = gf250(-1); a.value
            1125899906842678
        >>> a
            <shamirshare.GFpelt object at 0x7ff7dd6a52b0>
    """

    def __init__(self, prime):
        self.prime = prime

    def __contains__(self, theelt):  # Usage if(x in GFp(prime))
        return (self == theelt.field)

    def __call__(self, theint):      # Usage x = gp13(5)
        return(GFpelt(self, theint))

############################# Class GF8elt #################################
# Class GFpelt
# Elements of some finite field GF(p), for a specified prime integer p.

class GFpelt(object):
    """An element of GF(p) for some specified prime p
    We assume that there is only a single GFp in play at any time,
    with no attempt to catch attempts to combine elements of distinct fields.
    Usage:
        >>> from shamirshare import *
        >>> gf250 = GFp(1125899906842679)  # First prime larger than 2^50
        >>> a = gf250(-1); a.value
            1125899906842678
        >>> a
            <shamirshare.GFpelt object at 0x7ff7dd6a52b0>
        >>> format(2 * a)   # Integer '2' is coerced into GFp
            1125899906842677
    """

    def __init__(self, field, value):
        self.field = field
        self.value = value
        if isinstance(value, (GFpelt,)):
            self.value = value.value  # strip redundant GFpelt
        elif isIntType(value):
            self.value = self.__normalize(value)

    def __normalize(self, value):
        """Given an integer, return the smallest positive integer which is equivalent mod prime"""
        return(((value % self.field.prime) + self.field.prime) % self.field.prime)

    def __eq__(self, other):  # Implement for Python 2 & 3 with overloading
        if isIntType(other):
            otherval = self.__normalize(other)
        elif isinstance(other, (GFpelt,)):
            otherval = other.value
        return self.value == otherval

    def __ne__(self, other):  # Implement for Python 2 & 3 with overloading
        if isIntType(other):
            otherval = self.__normalize(other)
        elif isinstance(other, (GFpelt,)):
            otherval = other.value
        return self.value != otherval


    ######################## Addition Operators ###############################

    def add(self, summand):
        """add elements of GFpelt (overloaded to allow adding integers)"""
        if isIntType(summand):
            summand = self.field(summand)
        elif not isinstance(summand, (GFpelt,)):
            raise NotImplementedError("Can't add GFpelt object to {0:} object".format(type(summand)))
        return GFpelt(self.field, (self.value + summand.value) % self.field.prime)

    def neg(self):
        return GFpelt(self.field, (self.field.prime-self.value) % self.field.prime)

    def sub(self, summand):
        return self.add(summand.neg())


    ######################## Multiplication Operators ################################

    def mul(self, multip):  # Elementary multiplication in finite fields
        """multiply elements of GFpelt (overloaded to allow integers)"""
        if isIntType(multip):  # Coerce if multiplying integer
            multip = self.__normalize(multip)
        elif isinstance(multip, (GFpelt,)):
            multip = multip.value
        elif not isinstance(multip, (GFpelt,)):
            raise NotImplementedError("Can't multiply GFpelt object with {0:} object".format(type(multip)))
        return GFpelt(self.field, ((self.value * multip) % self.field.prime))


    ######################## Division Operators ######################################

    def inv(self):
        """inverse of element in GFp"""
        if (self.value == 0): raise ZeroDivisionError("Attempting to invert zero element of GFp")
        return GFpelt(self.field, GFpelt.__xgcd(self.value,self.field.prime)[1])

    @staticmethod
    def __xgcd(a, b):
        """xgcd(a,b) returns a tuple of form (g,x,y), where g is gcd(a,b) and
        x,y satisfy the equation g = ax + by."""
        a1 = 1; b1 = 0; a2 = 0; b2 = 1; aneg = 1; bneg = 1
        if(a < 0):
            a = -a; aneg = -1
        if(b < 0):
            b = -b; bneg = -1
        while (1):
            quot = -(a // b)
            a = a % b
            a1 = a1 + quot*a2; b1 = b1 + quot*b2
            if(a == 0):
                return (b, a2*aneg, b2*bneg)
            quot = -(b // a)
            b = b % a
            a2 = a2 + quot*a1; b2 = b2 + quot*b1
            if(b == 0):
                return (a, a1*aneg, b1*bneg)

    def div(self, divisor):
        """divide elements of GFpelt (overloaded to allow integers)"""
        if isIntType(divisor):  # Coerce if dividing by integer
            divisor = GFpelt(self.field, self.__normalize(divisor))
        elif not isinstance(divisor, (GFpelt,)):
            raise NotImplementedError("Can't divide GFpelt object by {0:} object".format(type(divisor)))
        return self.mul(divisor.inv())


############################# Polynomial Operations ###########################
# Polynomials are represented as a list of coefficients, but no explicit class
# is created.
###############################################################################

### Is this function needed?
@staticmethod
def __trimlist__(thelist):  # Remove trailing (high order) zeros in lists
    for x in reversed(thelist):
        if x == 0:  # Rely on overloading of __eq__ for coefficient ring
            del thelist[-1:]
        else:
            break
    return thelist

@staticmethod
def __addlists__(list1, list2):
    returnlist = [((list1[i] if (i < len(list1)) else 0) + (list2[i] if (i < len(list2)) else 0)) for i in range(max(len(list1), len(list2)))]
    return returnlist

def fit(thepoints,thefield=None):  # Lagrange Interpolation
    """Find the unique degree (n-1) polynomial fitting the n presented values,
    using Lagrange Interpolation.
    Usage: fit(((gf8(3),gf8('05')),(gf8(2),gf8('f4')),...)) returns a polynomial p such that p(3) = '05', ...
    Given a list ((x1,y1),(x2,y2),...,(xn,yn)), return the polynomials
    Sum(j, Prod(i!=j, yj*(x-xi)/(xj-xi)))"""
    if (thefield == None):
        thefield = thepoints[0][1].field      # Field of first y value
    ptslen = len(thepoints)
    thepoly = ptslen*[thefield(0)]
    xvals = [thefield(x) for x, y in thepoints]  # Should be a better way to do this
    yvals = [thefield(y) for x, y in thepoints]
    for i in range(ptslen):
        theterm = [thefield(1)] + (ptslen-1)*[thefield(0)]
        theprod = thefield(1)
        for j in (j for j in range(ptslen) if (i != j)):
            for k in range(ptslen-1,0,-1):  # Multiply theterm by (x - xi)
                theterm[k] = theterm[k].add(theterm[k-1])
                theterm[k-1] = theterm[k-1].mul(xvals[j]).neg()
            theprod = theprod.mul(xvals[i].sub(xvals[j]))
        theprod = yvals[i].div(theprod)
        for k in range(ptslen):
            thepoly[k] = thepoly[k].add(theterm[k].mul(theprod))
    return thepoly

def eval(poly, xvalue):  # Evaluate poly at given value using Horner's Rule
    polydeg = len(poly)-1
    theval = poly[polydeg]
    for theindex in range(polydeg-1, -1, -1):
        theval = theval.mul(xvalue).add(poly[theindex])
    return theval  # Note: Value is in polyring.coeffring, not polyring
