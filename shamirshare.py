###############################################################################
# SHAMIRSHARE.py
# The Shamir Key Share scheme, implemented over the finite fields
# GF8 (as featured in AES) and GF16, a quadratic extension of GF8
# Implement Shamir Secret Sharing mechanism over 8-bit, 16-bit,
# and prime fields as specified in the KMIP v2.0 protocol.
# Author: Robert Campbell, <r.campbel.256@gmail.com>
# Date: 4 Sept 2019
# Version 0.2
# License: Simplified BSD (see details at bottom)
###############################################################################

"""Code to perform a Shamir Secret Sharing split of a secret, as in KMIP v2.0.
Possible ground fields include:
    GF(2^8) - GF8, as used by AES
    GF(2^16) - GF16, a quadratic extension of the first (not yet implemented)
    GF(p) - GFp, for a specified prime p (not yet implemented)
Usage:  Implement a 3-of-7 KeySplit over GF(2^8)
        >>> from shamirshare import *
        >>> gf8 = GF8()                      # Create the field GF(2^8)
        >>> GF8x = PolyFieldUniv(gf8)        # Ring of polynomials over GF(2^8)
        ################### Create a new key/secret and split it
        >>> [(i,"{0:02x}".format(random.randint(0,256))) for i in range(1,4)] # Choose random splits
            [(1, '45'), (2, '41'), (3, 'c3')]
        >>> pfit = GF8x.fit(((1, '45'), (2, '41'), (3, 'c3'))); format(pfit)
            '[c7, 34, b6, ]'
        # So poly is ('c7' + '34'*x + 'c3'*x^2), and secret is pfit(0) = 'c7'
        # Now generate four more splits for users 4, 5, 6, and 7
        >>> [format(pfit(i)) for i in range(4,8)]
            ['82', '00', '04', '86']
        # So the splits are:  (1, '45'), (2, '41'), (3, 'c3'), (4, '82'), (5, '00'), (6, '04'), (7, '86')
        ################### Now recover the secret using splits for users 2, 4 and 7
        >>> pfit = GF8x.fit(((2, '41'), (4, '82'), (7, '86'))); format(pfit)
            '[c7, 34, b6, ]'
        >>> format(pfit(0))
            'c7'
        ################### Split the existing secret 'ab'
        >>> pfit = GF8x.fit(((0, 'ab'), (1, '45'), (2, '41'))); format(pfit)
            '[ab, 6e, 80, ]'
        # Now generate splits for users 3, 4, 5, 6, and 7
        >>> [(i, format(pfit(i))) for i in range(3,8)]
            [(3, 'af'), (4, 'd0'), (5, '3e'), (6, '3a'), (7, 'd4')]
Usage:  Implement a 4-of-5 KeySplit over GFp(13)
        >>> gf13 = shamirshare.GFp(13)
        >>> GFp13x = shamirshare.PolyFieldUniv(gf13)
        >>> pfit13 = GFp13x.fit(((1,3),(2,6),(3,-2),(4,0))); format(pfit13)
            '[7, 6, 6, 10, ]'
        >>> print(pfit13(5))   # The additional split for user #5
            7
        >>> print(pfit13(0))   # The resulting split secret
            7
    """

__version__ = '0.2'  # Format specified in Python PEP 396
Version = 'shamirshare.py, version ' + __version__ + ', 4 Sept, 2019, by Robert Campbell, <r.campbel.256@gmail.com>'

import random
import sys     # Check Python2 or Python3


def isStrType(x):
    if sys.version_info < (3,): return isinstance(x,(basestring,))
    else: return isinstance(x,(str,))


def isIntType(x):
    if sys.version_info < (3,): return isinstance(x, (int, long,))
    else: return isinstance(x, (int,))


def isListType(x):    # List or Tuple: [1,2] or (1,2)
    return isinstance(x, (list, tuple,))


############################# Class GF8elt #################################
# Class GF8
# A singleton class implementing the finite field GF8, as used in AES,
#   GF8 = GF(2^8) = GF(2)[x]/<x^8 + x^4 + x^3 + x + 1>, with the driving
#   (non-primitive) primitive polynomial x^8 + x^4 + x^3 + x + 1, aka "1b"
#   Elements of GF8 are instances of GF8elt.
#   (Defining this field as a class is not directly needed, but makes code
#   which is templated over GF8, GF16 and various GFp easier)

class GF8(object):
    """The finite field GF(2^8), as represented in AES
    (driving polynomial x^8 + x^4 + x^3 + x + 1, aka "1b")
    """

    instance = None

    def __new__(cls):
        if cls.instance is None:
            cls.instance = super().__new__(cls)
        return cls.instance

    def __contains__(self, elt):
        return isinstance(elt, (GF8elt,))

    def __call__(self, thevalue):
        return(GF8elt(thevalue))

    def __format__(self, fmtspec):  # Over-ride format conversion
        return "Finite field GF(2^8) mod (x^8 + x^4 + x^3 + x + 1)"


############################# Class GF8elt #################################
# Class GF8elt
# Elements of the finite field GF8 = GF(2^8) = GF(2)[x]/<x^8 + x^4 + x^3 + x + 1>,
#   with the driving (non-primitive) primitive polynomial x^8 + x^4 + x^3 + x + 1, aka "1b",
#   the representation of GF(2^8) used in the construction of the AES block cipher.

class GF8elt(object):
    """An element of GF(2^8) as represented in AES
    (driving polynomial x^8 + x^4 + x^3 + x + 1, aka "1b")
    Usage:
        >>> from shamirshare import *
        >>> a = GF8elt(123)            # Note that decimal '123' is hex 0x7b
        >>> a                             # Full representation
            <GF8elt object at 0x7f8daa662e80>
        >>> "{0:x}".format(a)             # Hex format
            '7b'
        >>> b = GF8elt('f5')
        >>> "{0:b}".format(a+b)           # Add, output binary: 0x7b xor 0xf5 = 0x8e = 0b10001110
            '10001110'
    """

    fmtspec = 'x'  # Default format for GF8 is two hex digits

    def __init__(self, value):
        if isinstance(value, (GF8elt,)): self.value = value.value  # strip redundant GF8elt
        if isinstance(value, (int,)): self.value = value
        elif isStrType(value): self.value = int(value,16)  # For the moment, assume hex

    def __eq__(self, other):  # Implement for both Python2 & 3 with overloading
        if isIntType(other): otherval = other
        elif isStrType(other): otherval = int(other, 16)
        elif isinstance(other, (GF8elt,)): otherval = other.value
        return self.value == otherval

    def __ne__(self, other):  # Implement for both Python2 & 3 with overloading
        if isIntType(other): otherval = other
        elif isStrType(other): otherval = int(other, 16)
        elif isinstance(other, (GF8elt,)): otherval = other.value
        return self.value != otherval

    ######################## Format Operators #################################

    def __format__(self, fmtspec):  # Over-ride format conversion
        """Override the format when outputting a GF8 element.
        A default can be set for the field or specified for each output.
        Possible formats are:
            b- coefficients as a binary integer
            x- coefficients as a hex integer
        Example:
            >>> a = GF8elt([1,1,0,1,1,1])
            >>> "{0:x}".format(a)
            '37'
            >>> "{0:b}".format(a)
            '00110111'"""
        if fmtspec == '': fmtspec = GF8elt.fmtspec  # Default format is hex
        if fmtspec == 'x': return "{0:02x}".format(self.value)
        if fmtspec == 'b': return "{0:08b}".format(self.value)

    def __str__(self):
        """over-ride string conversion used by print"""
        return '{0:x}'.format(self)

    def __int__(self):
        """convert to integer"""
        return self.value

    def __index__(self):
        """convert to integer for various uses including bin, hex and oct (Python 2.5+ only)"""
        return self.value

    if sys.version_info < (3,):  # Overload hex() and oct() (bin() was never backported to Python 2)
        def __hex__(self): return "0x{0:02x}".format(self.value)
        def __oct__(self): return oct(self.__index__())

    ######################## Addition Operators ###############################

    def add(self, summand):
        """add elements of GF8elt (overloaded to allow adding integers and lists of integers)"""
        if isinstance(summand, (int,)) or isStrType(summand):  # Coerce if adding integer or string and GF8elt
            summand = GF8elt(summand)
        elif isinstance(summand, (PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return summand.__add__(self)
        elif not isinstance(summand, (GF8elt,)):
            raise NotImplementedError("Can't add GF8elt object to {0:} object".format(type(summand)))
        return GF8elt(self.value ^ GF8elt(summand.value).value)

    def __add__(self, summand):   # Overload the "+" operator
        return self.add(summand)

    def __radd__(self, summand):  # Overload the "+" operator when first addend can be coerced to GF8elt
        return self.add(summand)  # Because addition is commutative

    def __iadd__(self, summand):  # Overload the "+=" operator
        self = self.add(summand)
        return self

    def __neg__(self):  # Overload "-" unary operator (no sense over GF(2))
        return self

    def __sub__(self, summand):  # Overload the "-" binary operator
        return self.add(summand)

    def __isub__(self, summand):  # Overload the "-=" operator
        self = self + summand
        return self

    ######################## Multiplication Operators #########################

    def mul(self, multand):  # Elementary multiplication in finite fields
        """multiply elements of GF8 (overloaded to allow integers and lists of integers)"""
        amult = self.value     # Pull it out of the GF8elt structure
        bmult = multand.value  # Pull it out of the GF8elt structure
        thenum = 0
        # Multiply as binary polynomials
        for i in range(8): thenum ^= ((bmult << i) if ((amult >> i) & 0x01) == 1 else 0)
        # And then reduce mod the driving polynomial of GF8
        return GF8elt(GF8elt.__reduceGF8(thenum))

    def __mul__(self, multip):  # Overload the "*" operator
        if isinstance(multip, (int,)) or isStrType(multip):  # Coerce if multiplying integer or string and GF8elt
            return self.mul(GF8elt(multip))
        elif isinstance(multip, (GF8elt,)):
            return self.mul(multip)
        elif isinstance(multip, (PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return multip.__mul__(self)
        else: raise NotImplementedError("Can't multiply GF8elt object with {0:} object".format(type(multip)))

    def __rmul__(self, multip):  # Overload the "*" operator when first multiplicand can be coerced to GF8elt
        return self.__mul__(multip)  # Because multiplication is commutative

    def __imul__(self, multip):  # Overload the "*=" operator
        self = self * multip
        return self

    @staticmethod
    def __reduceGF8(thevalue):  # Value is integer in range [0,2^16-1]
        reductable = (0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f)
        feedback = 0
        for i in range(8, 16): feedback ^= (reductable[i-8] if (((thevalue >> i) & 0x01) == 1) else 0)
        return ((thevalue & 0xff) ^ feedback)

    ######################## Division Operators ###############################

    # Table based inverse (well, actually pseudo-inverse, as 00-->00)
    __GF8inv = {
         "00":"00","01":"01","02":"8d","03":"f6","04":"cb","05":"52","06":"7b","07":"d1",
         "08":"e8","09":"4f","0a":"29","0b":"c0","0c":"b0","0d":"e1","0e":"e5","0f":"c7",
         "10":"74","11":"b4","12":"aa","13":"4b","14":"99","15":"2b","16":"60","17":"5f",
         "18":"58","19":"3f","1a":"fd","1b":"cc","1c":"ff","1d":"40","1e":"ee","1f":"b2",
         "20":"3a","21":"6e","22":"5a","23":"f1","24":"55","25":"4d","26":"a8","27":"c9",
         "28":"c1","29":"0a","2a":"98","2b":"15","2c":"30","2d":"44","2e":"a2","2f":"c2",
         "30":"2c","31":"45","32":"92","33":"6c","34":"f3","35":"39","36":"66","37":"42",
         "38":"f2","39":"35","3a":"20","3b":"6f","3c":"77","3d":"bb","3e":"59","3f":"19",
         "40":"1d","41":"fe","42":"37","43":"67","44":"2d","45":"31","46":"f5","47":"69",
         "48":"a7","49":"64","4a":"ab","4b":"13","4c":"54","4d":"25","4e":"e9","4f":"09",
         "50":"ed","51":"5c","52":"05","53":"ca","54":"4c","55":"24","56":"87","57":"bf",
         "58":"18","59":"3e","5a":"22","5b":"f0","5c":"51","5d":"ec","5e":"61","5f":"17",
         "60":"16","61":"5e","62":"af","63":"d3","64":"49","65":"a6","66":"36","67":"43",
         "68":"f4","69":"47","6a":"91","6b":"df","6c":"33","6d":"93","6e":"21","6f":"3b",
         "70":"79","71":"b7","72":"97","73":"85","74":"10","75":"b5","76":"ba","77":"3c",
         "78":"b6","79":"70","7a":"d0","7b":"06","7c":"a1","7d":"fa","7e":"81","7f":"82",
         "80":"83","81":"7e","82":"7f","83":"80","84":"96","85":"73","86":"be","87":"56",
         "88":"9b","89":"9e","8a":"95","8b":"d9","8c":"f7","8d":"02","8e":"b9","8f":"a4",
         "90":"de","91":"6a","92":"32","93":"6d","94":"d8","95":"8a","96":"84","97":"72",
         "98":"2a","99":"14","9a":"9f","9b":"88","9c":"f9","9d":"dc","9e":"89","9f":"9a",
         "a0":"fb","a1":"7c","a2":"2e","a3":"c3","a4":"8f","a5":"b8","a6":"65","a7":"48",
         "a8":"26","a9":"c8","aa":"12","ab":"4a","ac":"ce","ad":"e7","ae":"d2","af":"62",
         "b0":"0c","b1":"e0","b2":"1f","b3":"ef","b4":"11","b5":"75","b6":"78","b7":"71",
         "b8":"a5","b9":"8e","ba":"76","bb":"3d","bc":"bd","bd":"bc","be":"86","bf":"57",
         "c0":"0b","c1":"28","c2":"2f","c3":"a3","c4":"da","c5":"d4","c6":"e4","c7":"0f",
         "c8":"a9","c9":"27","ca":"53","cb":"04","cc":"1b","cd":"fc","ce":"ac","cf":"e6",
         "d0":"7a","d1":"07","d2":"ae","d3":"63","d4":"c5","d5":"db","d6":"e2","d7":"ea",
         "d8":"94","d9":"8b","da":"c4","db":"d5","dc":"9d","dd":"f8","de":"90","df":"6b",
         "e0":"b1","e1":"0d","e2":"d6","e3":"eb","e4":"c6","e5":"0e","e6":"cf","e7":"ad",
         "e8":"08","e9":"4e","ea":"d7","eb":"e3","ec":"5d","ed":"50","ee":"1e","ef":"b3",
         "f0":"5b","f1":"23","f2":"38","f3":"34","f4":"68","f5":"46","f6":"03","f7":"8c",
         "f8":"dd","f9":"9c","fa":"7d","fb":"a0","fc":"cd","fd":"1a","fe":"41","ff":"1c"
        }

    def inv(self):
        """inverse of element in GF8"""
        if (self.value == 0): raise ZeroDivisionError("Attempting to invert zero element of GF8")
        # Tableized (lazy solution for a small field, xgcd is better solution)
        return GF8elt(GF8elt.__GF8inv[str(self)])

    def div(self, divisor):
        """divide elements of GF8"""
        return self * divisor.inv()

    def __div__(self, divisor):  # Overload the "/" operator in Python2
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self * divisor.inv()

    def __truediv__(self, divisor):  # Overload the "/" operator in Python3
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self * divisor.inv()

    # As GF8 is a field, there is no real need for floordiv, but include it
    # as someone will try "//" in any event - if only in error

    def __floordiv__(self, divisor):  # Overload "//" operator in Python 2 & 3
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self * divisor.inv()

    def __rdiv__(self, dividend):
        if isinstance(dividend, (int,)) or isStrType(dividend):  # Coerce if dividing integer or string
            dividend = GF8elt(dividend)
        return dividend * self.inv()

    def __rtruediv__(self, dividend):  # Overload the "/" operator in Python3
        if isinstance(dividend, (int,)) or isStrType(dividend):  # Coerce if dividing by integer or string
            dividend = GF8elt(dividend)
        return dividend * self.inv()

    def __rfloordiv__(self, dividend):  # Overload "//" operator in Python2 & 3
        if isinstance(dividend, (int,)) or isStrType(dividend):  # Coerce if dividing by integer or string
            dividend = GF8elt(dividend)
        return dividend * self.inv()

    def __idiv__(self, divisor):  # Overload the "/=" operator in Python2
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self.div(divisor)

    def __ifloordiv__(self, divisor):  # Overload the "//=" operator
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self.div(divisor)

    def __itruediv__(self, divisor):  # Overload the "//=" operator in Python3
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = GF8elt(divisor)
        return self.div(divisor)


############################# Class GFp #################################
# Class GFp
# A singleton class implementing the finite field GF(p), where p is a
#   specified prime integer.

class GFp(object):
    """A prime field, given some specified prime p
    Usage:
        >>> from shamirshare import *
        >>> gf250 = GFp(1125899906842679)  # First prime larger than 2^50
        >>> gf250
            <shamirshare.GFp object at 0x7ff7dd8767f0>
        >>> format(gf250)
            'Field of integers mod prime 1125899906842679'
        >>> a = gf250(-1); format(a)
            1125899906842678
        >>> a
            <shamirshare.GFpelt object at 0x7ff7dd6a52b0>
    """

    def __init__(self, prime):
        self.prime = prime

    def __contains__(self, theelt):
        return (self == theelt.field)

    def __call__(self, theint):
        return(GFpelt(self, theint))

    def __format__(self, fmtspec):  # Over-ride format conversion
        return "Field of integers mod prime {0:}".format(self.prime)


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
        >>> a = gf250(-1); format(a)
            1125899906842678
        >>> a
            <shamirshare.GFpelt object at 0x7ff7dd6a52b0>
        >>> format(2*a)
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

    ######################## Format Operators #################################

    def __format__(self, fmtspec):  # Over-ride format conversion
        if fmtspec == '': return "{0:}".format(self.value)  # Default format is decimal
        if fmtspec == 'x': return "{0:x}".format(self.value)
        if fmtspec == 'b': return "{0:b}".format(self.value)

    def __str__(self):
        """over-ride string conversion used by print"""
        return '{0:}'.format(self.value)

    def __int__(self):
        """convert to integer"""
        return self.value

    def __index__(self):
        """convert to integer for various uses including bin, hex and oct (Python 2.5+ only)"""
        return self.value

    if sys.version_info < (3,):  # Overload hex() and oct() (bin() was never backported to Python 2)
        def __hex__(self): return "0x{0:x}".format(self.value)
        def __oct__(self): return oct(self.__index__())

    ######################## Addition Operators ###############################

    def add(self,summand):
        """add elements of GFpelt (overloaded to allow adding integers)"""
        if isIntType(summand):
            summand = self.field(summand)
        elif isinstance(summand, (PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return summand.add(self)
        elif not isinstance(summand, (GFpelt,)):
            raise NotImplementedError("Can't add GFpelt object to {0:} object".format(type(summand)))
        return GFpelt(self.field, (self.value + summand.value) % self.field.prime)

    def __add__(self,summand):   # Overload the "+" operator
        return self.add(summand)

    def __radd__(self,summand):  # Overload the "+" operator
        return self.add(summand)  # Because addition is commutative

    def __iadd__(self,summand): # Overload the "+=" operator
        self = self.add(summand)
        return self

    def __neg__(self):  # Overload the "-" unary operator
        return GFpelt(self.field, (self.field.prime-self.value) % self.field.prime)

    def __sub__(self,summand):  # Overload the "-" binary operator
        return self.add(-summand)

    def __isub__(self,summand): # Overload the "-=" operator
        self = self.add(-summand)
        return self

    ######################## Multiplication Operators ################################

    def mul(self, multip):  # Elementary multiplication in finite fields
        """multiply elements of GFpelt (overloaded to allow integers)"""
        if isIntType(multip):  # Coerce if multiplying integer
            multip = self.__normalize(multip)
        elif isinstance(multip, (GFpelt,)):
            multip = multip.value
        elif isinstance(multip, (PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return multip.mul(self)
        elif not isinstance(multip, (GFpelt,)):
            raise NotImplementedError("Can't multiply GFpelt object with {0:} object".format(type(multip)))
        return GFpelt(self.field, ((self.value * multip) % self.field.prime))

    def __mul__(self, multip):  # Overload the "*" operator
        return self.mul(multip)

    def __rmul__(self, multip):  # Overload the "*" operator when first multiplicand can be coerced to GFpelt
        return self.mul(multip)  # Because multiplication is commutative

    def __imul__(self, multip):  # Overload the "*=" operator
        self = self.mul(multip)
        return self

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
        return self * divisor.inv()

    def __div__(self, divisor):  # Overload the "/" operator in Python2
        return self.div(divisor)

    def __truediv__(self, divisor):  # Overload the "/" operator in Python3
        return self.div(divisor)

    # As GFp is a field, there is no real need for floordiv, but include it
    # as someone will try "//" in any event - if only in error

    def __floordiv__(self, divisor):  # Overload the "//" operator in Python2/3
        return self.div(divisor)

    def __rdiv__(self, dividend):
        """divide elements of GFpelt (overloaded to allow integers)"""
        if isIntType(dividend):  # Coerce dividing integer by GFpelt
            dividend = GFpelt(self.field, self.__normalize(dividend))
        elif not isinstance(dividend, (GFpelt, )):
            raise NotImplementedError("Can't divide {0:} object by GFpelt object".format(type(dividend)))
        return dividend * self.inv()

    def __rtruediv__(self, dividend):  # Overload the "/" operator in Python3
        return self.__rdiv__(dividend)

    def __rfloordiv__(self, dividend):  # Overload the "//" operator in Python2 and Python3
        return self.__rdiv__(dividend)

    def __idiv__(self, divisor):  # Overload the "/=" operator in Python2
        return self.div(divisor)

    def __ifloordiv__(self, divisor):  # Overload the "//=" operator
        return self.div(divisor)

    def __itruediv__(self, divisor):  # Overload the "//=" operator in Python3
        return self.div(divisor)


############################# Class PolyFieldUniv #############################
# Class PolyFieldUniv
# A univariable polynomial ring over a specified field of coefficients.
#   A simple container class for PolyFieldUnivElt objects.
###############################################################################

class PolyFieldUniv(object):
    """Polynomial Ring with a single variable (univariate) over
       a specified field of coefficients.
    Usage:
        >>> from shamirshare import *
        >>> GF8x = shamirshare.PolyFieldUniv()         # Default GF8elt coeffring
        >>> p3 = shamirshare.PolyFieldUnivElt(GF8x,[1,2,3])
        >>> format(p3)
        '[01, 02, 03, ]'
        """

    def __init__(self, coeffring=type(GF8()), var='x', fmtspec="l"):
        self.coeffring = coeffring       # Set the coefficient ring (well, actually field)
        self.var = var                   # Used by polynomial format output
        self.fmtspec = fmtspec           # p=polynomial; c=coeffsonly; l=list of coeffs

    def __format__(self, fmtspec):  # Over-ride format conversion
        """Override the format when outputting a PolyFieldUniv element."""
        return("Polynomial ring with coeffs in {0:} and variable \"{1:}\"".format(self.coeffring, self.var))

    def __call__(self, elts):  # Coerce constant or array of coeffs
        if isinstance(elts, PolyFieldUnivElt):  # Handle unnecessary coercion
            return elts
        elif isListType(elts):              # List or Sequence
            return PolyFieldUnivElt(self, list(map(self.coeffring, elts)))
        elif isIntType(elts) or isStrType(elts):  # Overload int/string --> constant poly
            self.coeffs = [self.coeffring(elts)]
        else:
            return PolyFieldUnivElt(self, [self.coeffring(elts)])  # Coerce coeff as constant poly

    def fit(self, thepoints):  # Lagrange Interpolation
        """Find the unique degree (n-1) polynomial fitting the n presented values,
        using Lagrange Interpolation.
        Usage: fit(((3,'05'),(2,'f4'),...)) returns a polynomial p such that p(3) = '05', ...
        Given a list ((x1,y1),(x2,y2),...,(xn,yn)), return the polynomials
        Sum(j, Prod(i!=j, yj*(x-xi)/(xj-xi)))"""
        thepoly = PolyFieldUnivElt(self,[])
        xvals = [self.coeffring(x) for x,y in thepoints]  # Should be a better way to do this
        yvals = [self.coeffring(y) for x,y in thepoints]
        ptslen = sum(1 for k in xvals)
        for j in range(ptslen):  # Compute len of xvals
            theterm = PolyFieldUnivElt(self,[1])
            theprod = self.coeffring(1)
            for i in (i for i in range(ptslen) if i!=j):
                theterm *= PolyFieldUnivElt(self,[-xvals[i],1])       # Multiply by (1*x - xi)
                theprod *= (xvals[j] - xvals[i])
            thepoly += (yvals[j]*theterm/theprod)
        return thepoly

############################# Class PolyFieldUnivElt ################################
# Class PolyFieldUnivElt
# Elements of the univariate polynomial ring with coefficients in a field.
#   Only those functions are implemented for cases where the coefficient field
#   is one of GF(2^8)AES, GF(2^16) or eventually a prime field, as needed to
#   implement Shamir secret sharing as specified in KMIP v2.0.
#####################################################################################

class PolyFieldUnivElt(object):
    """An element of the ring of univariate polynomails with coefficients in
       GF(2^8), GF(2^16) or a prime field, GFp.
    Usage:
        >>> from shamirshare import *
        >>> GF8x = PolyFieldUniv()   # Polynomial Ring: default GF8elt coeffs
        >>> p3 = PolyFieldUnivElt(GF8x,[1,2,3])
        >>> format(p3)
        '[01, 02, 03, ]'
        >>> p3
        <PolyFieldUnivElt object at 0x7f0255faee10>
        >>> p2 = PolyFieldUnivElt(GF8x,[1,3])
        >>> format(p3+p2)
        '[00, 01, 03, ]'
        >>> format(p3*p2)
        '[01, 01, 05, 05, ]'
    """

    def __init__(self, polyring, coeffs):
        self.polyring = polyring
        if isinstance(coeffs, (PolyFieldUnivElt,)):  # Cloning an element
            self.coeffs = [self.polyring.coeffring(thecoeff) for thecoeff in coeffs.coeffs]
        elif isIntType(coeffs) or isStrType(coeffs):  # Overload int/string --> constant poly
            self.coeffs = [self.polyring.coeffring(coeffs)]
        elif isListType(coeffs):                       # Overload list --> poly
            coeffs = PolyFieldUnivElt.__trimlist__(coeffs)         # Remove trailing (high order) zeros
            self.coeffs = [self.polyring.coeffring(thecoeff) for thecoeff in coeffs]
        elif (coeffs in self.polyring.coeffring):      # Overload coeffring elt --> constant poly
            self.coeffs = [coeffs]

    @staticmethod
    def __trimlist__(thelist):  # Remove trailing (high order) zeros in lists
        for x in reversed(thelist):
            if x == 0:  # Rely on overloading of __eq__ for coefficient ring
                del thelist[-1:]
            else:
                break
        return thelist

    def __eq__(self, other):  # Implement for Python 2 & 3 with overloading
        if isIntType(other) or isStrType(other) or isListType(other) or (other in self.polyring.coeffring):
            otherpoly = PolyFieldUnivElt(self.polyring,other)
        else: otherpoly = other
        return self.coeffs == otherpoly.coeffs

    def __ne__(self, other):  # Implement for Python 2 & 3 with overloading
        if isIntType(other) or isStrType(other) or isListType(other) or (other in self.polyring.coeffring):
            otherpoly = PolyFieldUnivElt(self.polyring,other)
        else:
            otherpoly = other
        return self.coeffs == otherpoly.coeffs

    ######################## Format Operators #################################

    def __format__(self, fmtspec):  # Over-ride format conversion
        """Override the format when outputting a PolyFieldUnivElt element.
        Possible formats are:
            l - list of coefficients
            p - polynomial format with specified variable
        """
        if fmtspec == '': fmtspec = 'l'  # Default format is list
        if fmtspec == 'l': return "["+"".join([(format(thecoeff)+", ") for thecoeff in self.coeffs])+"]"
        if fmtspec == 'p': raise NotImplementedError("polynomial format for PolyFieldUnivElt is not yet implemented")

    def __str__(self):
        """over-ride string conversion used by print"""
        return '{0:l}'.format(self)

    ######################## Addition Operators ###############################

    @staticmethod
    def __addlists__(list1, list2):
        returnlist = [((list1[i] if i<len(list1) else 0) + (list2[i] if i<len(list2) else 0)) for i in range(max(len(list1),len(list2)))]
        return returnlist

    def add(self, summand):
        """add elements of PolyFieldUnivElt (overloaded to allow adding integers and lists of integers)"""
        if isinstance(summand, (PolyFieldUnivElt,)):
            summand = summand  # Just multiplying
        elif isListType(summand):
            # Coerce if adding list, elts are coerceable into coeff ring
            summand = PolyFieldUnivElt(self.polyring, [self.polyring.coeffring(thecoeff) for thecoeff in summand])
        elif isinstance(summand, (int,)) or isStrType(summand) or (summand in self.polyring.coeffring):  # Coerce if adding integer or string and GF8elt
            summand = PolyFieldUnivElt(self.polyring, summand)
        else:
            raise NotImplementedError("Can't add PolyFieldUnivElt object to {0:} object".format(type(summand)))
        thecoeffs = PolyFieldUnivElt.__addlists__(self.coeffs, summand.coeffs)
        thecoeffs = PolyFieldUnivElt.__trimlist__(thecoeffs)
        return PolyFieldUnivElt(self.polyring, thecoeffs)

    def __add__(self, summand):   # Overload the "+" operator
        if isIntType(summand) or isStrType(summand) or isListType(summand):  # Coerce if adding integer, string or list
            return self.add(PolyFieldUnivElt(self.polyring, summand))
        else:
            return self.add(summand)

    def __radd__(self, summand):  # Overload the "+" operator when first addend can be coerced to ring of coeffs
        return self.__add__(summand)  # Because addition is commutative

    def __iadd__(self, summand):  # Overload the "+=" operator
        self = self + summand
        return self

    def __neg__(self):  # Overload the "-" unary operator (not over GF(2))
        return PolyFieldUnivElt(self.polyring, [-thecoeff for thecoeff in self.coeffs])

    def __sub__(self, summand):  # Overload the "-" binary operator
        return self.__add__(-summand)

    def __isub__(self, summand):  # Overload the "-=" operator
        self = self - summand
        return self

    ######################## Multiplication Operators #########################

    def mul(self, multand):  # Elementary multiplication of polynomials
        """multiply polynomials (overloaded to allow integers and lists of integers)"""
        if isinstance(multand, (PolyFieldUnivElt,)):
            multand = multand  # Just multiplying
        elif isListType(multand):
            # Coerce if multiplying list, elts are coerceable into coeff ring
            multand = PolyFieldUnivElt(self.polyring, [self.polyring.coeffring(thecoeff) for thecoeff in multand])
        elif isinstance(multand, (int,)) or isStrType(multand) or (multand in self.polyring.coeffring):  # Coerce if adding integer or string and GF8elt
            multand = PolyFieldUnivElt(self.polyring, multand)
        else:
            raise NotImplementedError("Can't multiply PolyFieldUnivElt object by {0:} object".format(type(multand)))
        polydeg = len(self.coeffs)+len(multand.coeffs)-2
        thelist = [self.polyring.coeffring(0) for i in range(polydeg+1)]
        for d in range(polydeg+1):
            thelist[d] = sum(self.coeffs[d-i]*multand.coeffs[i] for i in range(max(0, d-len(self.coeffs)+1), min(d+1, len(multand.coeffs))))
        return PolyFieldUnivElt(self.polyring, thelist)

    def __mul__(self, multand):  # Overload the "*" operator
        return self.mul(multand)

    def __rmul__(self,multand):  # Overload the "*" operator
        return self.mul(multand)

    def __imul__(self,multand): # Overload the "*=" operator
        self = self.mul(multand)
        return self

    ######################## Division Operators ######################################

    # Not needed (I think) for Shamir SS
    # BUT ... Do need to implement division of polynomial by constant

    def div(self, divisor):  # Elementary poly division (but only by constants)
        """divide polynomials - for shamirshare only need case of dividing by constants
        (overloaded to allow integers and lists of integers)
        As the coefficient ring (self.polyring.coeffring) is assumed to be a field, we combine floordiv and truediv functions."""
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        elif not (divisor in self.polyring.coeffring):
            raise NotImplementedError("Can't divide PolyFieldUnivElt object by {0:} object".format(type(divisor)))
        if (divisor == 0): raise ZeroDivisionError("Attempting to divide polynomial by zero element of coefficient ring")
        for i in range(len(self.coeffs)): self.coeffs[i] /= divisor
        return self

    def __div__(self, divisor):  # Overload the "/" operator in Python2
        return self.div(divisor)

    def __truediv__(self, divisor):  # Overload the "/" operator in Python3
        return self.div(divisor)

    def __floordiv__(self, divisor):  # Overload "//" operator in Python2 & 3
        return self.div(divisor)

    def idiv(self, divisor):  # In-place poly division (but only by constants)
        """in-place divide polynomials - for shamirshare only need case of
        dividing by constants (overloaded to allow integers).  As the
        coefficient ring (self.polyring.coeffring) is assumed to be a field,
        we combine floordiv and truediv functions."""
        if isinstance(divisor, (int,)) or isStrType(divisor):  # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        elif not (divisor in self.polyring.coeffring):
            raise NotImplementedError("Can't divide PolyFieldUnivElt object by {0:} object".format(type(divisor)))
        if (divisor == 0): raise ZeroDivisionError("Attempting to divide polynomial by zero element of coefficient ring")
        for i in range(len(self.coeffs)): self.coeffs[i] /= divisor
        return self

    def __idiv__(self, divisor):  # Overload the "/=" operator in Python2
        return self.idiv(divisor)

    def __ifloordiv__(self, divisor):  # Overload the "//=" operator
        return self.idiv(divisor)

    def __itruediv__(self, divisor):  # Overload the "//=" operator in Python3
        return self.idiv(divisor)

    ######################## Other Operators ##################################

    def eval(self, xvalue):  # Evaluate poly at given value using Horder's Rule
        polydeg = len(self.coeffs)-1
        theval = self.coeffs[polydeg]
        for theindex in range(polydeg-1, -1, -1):
            theval = theval*xvalue + self.coeffs[theindex]
        return theval  # Note: Value is in polyring.coeffring, not polyring

    # Allow usage "p1(123)" to evaluate polynomial p1 at the value 123
    def __call__(self, value):
        return self.eval(value)

# Thoughts and Bugs:
#   - Should class(elt) be a deep copy or should it just return elt?
#   - Implement GF8elt.random() to get random elements
#   - Need to implement GF(2^16) and GF(prime)

############################################################################
# License: Freely available for use, abuse and modification
# (this is the Simplified BSD License, aka FreeBSD license)
# Copyright 2018-2019 Robert Campbell. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#    1. Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#
#    2. Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in
#       the documentation and/or other materials provided with the distribution
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
############################################################################
