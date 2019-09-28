###############################################################################
# SHAMIRSHARE2.py
# Simplified implementation of the Shamir Secret Sharing mechanism over 8-bit,
# 16-bit, and prime fields as specified in the KMIP v2.0 protocol.
# Operator overloading is not used, neither is type coercion outside
# of __init__()
# Author: Robert Campbell, <r.campbel.256@gmail.com>
# Date: 27 Sept 2019
# Version 0.32
# License: Simplified BSD (see details at bottom)
###############################################################################

"""Code to perform a Shamir Secret Sharing split of a secret, as in KMIP v2.0.
Possible ground fields include:
    GF(2^8) - GF8, as specified by AES block cipher
    GF(2^16) - GF16, a quadratic extension of GF8
    GF(p) - GFp, for a specified prime p

    Usage:  ########## Implement a 3-of-5 KeySplit over GF(101) ###########

        >>> from shamirshare2 import *
        >>> gf101 = GFp(101)                 # Create the field GF(101)

        ###### Create a new key/secret and split it
        # Choose three random splits: 1-->35, 2-->92, 3-->11
        >>> pfit = fit(((1,35),(2,92),(3,11)),gf101); [pfit[i].value for i in range(3)]
        [42, 62, 32]

        # So poly is (42 + 62*x + 32*x^2), and secret is pfit(0) = 42 (Life, the Universe, ...)
        # Now generate two more splits for users 4 and 5
        >>> [eval(pfit,i).value for i in range(4,6)]
        [95, 41]

        # So the splits are:  1-->35, 2-->92, 3-->11, 4-->95, 5-->41
        # Now recover the secret using splits for users 1, 4 and 5
        >>> pfit2 = fit(((1,35),(4,95),(5,41)),gf101); [pfit2[i].value for i in range(3)]
        [42, 62, 32]
        >>> eval(pfit2,0).value         # Evaluate pfit2(0), same as its constant term
        42

    Usage:  ########### Implement a 3-of-4 KeySplit over GF8 #############

        >>> gf8 = GF8()                 # Create the field GF(2^8)

        ###### Create a new key/secret and split it
        # Choose three random splits: 1-->0x45, 2-->0x41, 3-->0xc3
        >>> pfit8 = fit(((gf8(1), gf8('45')), (gf8(2), gf8('41')), (gf8(3), gf8('c3'))))
        >>> list(map(format, pfit8))     # Coefficients of the polynomial
        ['c7', '34', 'b6']

        # So poly is (c7 + 34*x + b6*x^2), and secret is pfit8(0) = c7
        >>> format(eval(pfit8, gf8(4)))  # Split for user #4
        '82'

        ###### Now recover secret using splits for users 1, 3, 4
        >>> pfit8a = fit(((gf8(1), gf8('45')), (gf8(3), gf8('c3')), (gf8(4), gf8('82'))))
        >>> format(pfit8a[0])     # Constant term of pfit2, so value at 0
        'c7'

    Usage:  ########## Implement a 3-of-5 KeySplit over GF(2^16) ##########

        >>> gf16 = GF16()                 # Create the field GF(2^8)

        ###### Create a new key/secret and split it
        # Three random splits: 1-->(ab+cd*z), 2-->(11+ab*z), 5-->(1a+2b*z)
        >>> pfit16 = fit(((gf16(1),gf16(["ab","cd"])), (gf16(2),gf16(["11","ab"])), (gf16(5),gf16(["1a","2b"]))))
        >>> list(map(format, pfit16))      # Coefficients of the polynomial
        ['[ab, 34]', '[c2, 19]', '[c2, e0]']
        >>> print(eval(pfit16, gf16(3)))   # The additional split for user #3
        [11, 52]
        >>> print(eval(pfit16, gf16(4)))   # The additional split for user #4
        [1a, d2]
        >>> print(eval(pfit16, gf16(0)))   # The split secret, pfit16(0)
        [ab, 34]
"""

__version__ = '0.32'  # Format specified in Python PEP 396
Version = 'shamirshare2.py, version ' + __version__ + ', 27 Sept, 2019, by Robert Campbell, <r.campbel.256@gmail.com>'

import six        # Python2/3 compatibility
import functools  # reduce operator in Python3

############################# Class GFp #################################
# Class GFp
# A singleton class implementing the finite field GF(p), where p is a
#   specified prime integer.

class GFp(object):
    """A prime field, given some specified prime p
    Usage:
        >>> gf250 = GFp(1125899906842679)  # First prime larger than 2^50
        >>> a = gf250(-1); a.value
        1125899906842678
        >>> a                              #doctest: +ELLIPSIS
        <shamirshare2.GFpelt object at 0x...>
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
        >>> gf250 = GFp(1125899906842679)  # First prime larger than 2^50
        >>> a = gf250(-1); a.value
        1125899906842678
        >>> a                              #doctest: +ELLIPSIS
        <shamirshare2.GFpelt object at 0x...>
        >>> gf250(2).mul(a).value          # 2*(-1) mod p
        1125899906842677
    """

    def __init__(self, field, value):
        self.field = field
        self.value = value
        if isinstance(value, (GFpelt,)):
            self.value = value.value  # strip redundant GFpelt
        elif isinstance(value, six.integer_types):
            self.value = self.__normalize(value)

    def __normalize(self, value):
        """Given an integer, return the smallest positive integer which is equivalent mod prime"""
        return(((value % self.field.prime) + self.field.prime) % self.field.prime)

    def __eq__(self, other):  # Implement for Python 2 & 3 with overloading
        if isinstance(other, six.integer_types):
            otherval = self.__normalize(other)
        elif isinstance(other, (GFpelt,)):
            otherval = other.value
        return self.value == otherval

    def __ne__(self, other):  # Implement for Python 2 & 3 with overloading
        if isinstance(other, six.integer_types):
            otherval = self.__normalize(other)
        elif isinstance(other, (GFpelt,)):
            otherval = other.value
        return self.value != otherval


    ######################## Addition Operators ###############################

    def add(self, summand):
        """add elements of GFpelt (overloaded to allow adding integers)"""
        if isinstance(summand, six.integer_types):
            summand = self.field(summand)
        elif not isinstance(summand, (GFpelt,)):
            raise NotImplementedError("Can't add GFpelt object to {0:} object".format(type(summand)))
        return GFpelt(self.field, (self.value + summand.value) % self.field.prime)

    def neg(self):
        return GFpelt(self.field, (self.field.prime-self.value) % self.field.prime)

    def sub(self, summand):
        return self.add(summand.neg())


    ######################## Multiplication Operators #########################

    def mul(self, multip):  # Elementary multiplication in finite fields
        """multiply elements of GFpelt (overloaded to allow integers)"""
        if isinstance(multip, six.integer_types):  # Coerce if multiplying integer
            multip = self.__normalize(multip)
        elif isinstance(multip, (GFpelt,)):
            multip = multip.value
        elif not isinstance(multip, (GFpelt,)):
            raise NotImplementedError("Can't multiply GFpelt object with {0:} object".format(type(multip)))
        return GFpelt(self.field, ((self.value * multip) % self.field.prime))

    ######################## Division Operators ###############################

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
        if isinstance(divisor, six.integer_types):  # Coerce if dividing by integer
            divisor = GFpelt(self.field, self.__normalize(divisor))
        elif not isinstance(divisor, (GFpelt,)):
            raise NotImplementedError("Can't divide GFpelt object by {0:} object".format(type(divisor)))
        return self.mul(divisor.inv())


################################ Class GF8 ####################################
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

    _instance = None

    def __new__(cls):
        if not isinstance(cls._instance, cls):
            cls._instance = object.__new__(cls)
        return cls._instance

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
        >>> a = GF8elt(123)            # Note that decimal '123' is hex 0x7b
        >>> a                          #doctest: +ELLIPSIS
        <shamirshare2.GF8elt object at 0x...>
        >>> "{0:x}".format(a)          # Hex format
        '7b'
        >>> b = GF8elt('f5')
        >>> "{0:b}".format(a.add(b))   # Add, output binary: 0x7b xor 0xf5 = 0x8e = 0b10001110
        '10001110'
        >>> c = GF8elt([1,1,1,0,1,1])
        >>> "{0:b}".format(c)          # Integer vs list reverses printed bits
        '00110111'
        >>> format(c.mul(b),'x')       # Multiply b*c, output in hex
        'bd'
    """

    fmtspec = 'x'  # Default format for GF8 is two hex digits

    def __init__(self, value):
        self.value = 0
        self.field = GF8()
        if isinstance(value, (GF8elt,)): self.value = value.value  # strip redundant GF8elt
        elif isinstance(value, six.integer_types): self.value = value
        elif isinstance(value, six.string_types): self.value = int(value, 16)  # For the moment, assume hex
        elif isinstance(value, (list, tuple,)): self.value = functools.reduce(lambda a, x: 2*a + x, reversed(value), 0)
        else: raise ValueError("A GF8elt object cannot be constructed from input \'{0:}\' of type {1:}".format(value, type(value)))

    def __eq__(self, other):  # Implement for both Python2 & 3 with overloading
        return self.value == other.value

    def __ne__(self, other):  # Implement for both Python2 & 3 with overloading
        return self.value != other.value

    ######################## Format Operators #################################

    def __format__(self, fmtspec):  # Over-ride format conversion
        """Override the format when outputting a GF8 element.
        A default can be set for the field or specified for each output.
        Possible formats are:
            b- coefficients as a binary integer
            x- coefficients as a hex integer

        Usage:

            >>> a = GF8elt([1,1,1,0,1,1])
            >>> "{0:b}".format(a)       # Integer vs list reverses bit order
            '00110111'
            >>> "{0:x}".format(a)
            '37'"""
        if fmtspec == '': fmtspec = GF8elt.fmtspec  # Default format is hex
        if fmtspec == 'x': return "{0:02x}".format(self.value)
        elif fmtspec == 'b': return "{0:08b}".format(self.value)
        else: raise ValueError("The format string \'{0:}\' doesn't make sense (or isn't implemented) for a GF8elt object".format(fmtspec))

    def __str__(self):
        """over-ride string conversion used by print"""
        return '{0:x}'.format(self)

    def __int__(self):
        """convert to integer"""
        return self.value

    def __index__(self):
        """convert to integer for various uses including bin, hex and oct (Python 2.5+ only)"""
        return self.value

    if six.PY2:  # Overload hex() and oct() (bin() was never backported to Python 2)
        def __hex__(self): return "0x{0:02x}".format(self.value)
        def __oct__(self): return oct(self.__index__())

    ######################## Addition Operators ###############################

    def add(self, summand):
        """add elements of GF8elt"""
        return GF8elt(self.value ^ GF8elt(summand.value).value)

    def neg(self):  # x == -x when over GF2
        return self

    def sub(self, subtrahend):  # x - y == x + y when over GF2
        return self.add(subtrahend)

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
        return self.mul(divisor.inv())


############################# Class GF16 #################################
# Class GF16
# A singleton class implementing the finite field GF16, where GF16 is the
#   quadratic extension of GF8 defined by GF16 = GF8[z]/<z^2 + z + 3A>.
#   Elements of GF16 are instances of GF16elt.
#   (Defining this field as a class is not directly needed, but makes code
#   which is templated over GF8, GF16 and various GFp easier)

class GF16(object):
    """The finite field GF(2^16), as represented by
    GF16 = GF8[z]/<z^2 + z + 3A>, where GF8 is the field used in AES.
    """

    _instance = None
    basefield = GF8()    # Instantiate the base field GF8
    m = basefield('3A')  # Coeff in defining poly of GF16

    def __new__(cls, *args, **kwargs):
        if not isinstance(cls._instance, cls):
            cls._instance = object.__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self, var='z', fmtspec='x'):
        # Defaults: var (for poly print) 'z'; fmtspec is list of coeffs in hex
        self.var = var
        self.fmtspec = fmtspec

    def __contains__(self, elt):
        return isinstance(elt, (GF16elt,))

    def __call__(self, thevalue):
        return(GF16elt(thevalue))

    def __format__(self, fmtspec):  # Over-ride format conversion
        return "Finite field GF(2^16) = GF8[z]/<z^2 + z + 3A>"

############################# Class GF16elt #################################
# Class GF16elt
# Elements of the finite field GF16 = GF(2^16) = GF8[z]/<z^2 + z + 3A>,
#   where GF8 is the finite field used in the construction of the AES cipher.

class GF16elt(object):
    """An element of GF(2^16) represented as a quadratic extension of GF8, the
    finited field used in AES.  GF16elt instances are represented as linear
    polynomials with coefficients in GF8.
    Usage:
        >>> a = GF16elt(["ab","cd"])      # (ab) + (cd)*z, where (ab), (cd) are in GF(2^8)
        >>> a                             #doctest: +ELLIPSIS
        <shamirshare2.GF16elt object at 0x...>
        >>> "{0:x}".format(a)    # Hex format (list of GF8 coeffs, each in hex)
        '[ab, cd]'
        >>> format(a,'p')        # Polynomial format (with coeffs in GF8)
        '(ab) + (cd)*z'
        >>> b = GF16elt(5); format(b)
        '[05, 00]'
        >>> format((a.mul(b)).add(a.inv().mul(b)))  # Compute (a*b) + (b/a)
        '[9e, 7c]'
    """

    coeffs = []
    gf16 = GF16()  # Instantiate the field
    fmtspec = gf16.fmtspec
    field = gf16

    def __init__(self, value):
        self.field = GF16()
        if isinstance(value, (GF16elt,)):
            self.coeffs = value.coeffs  # strip redundant GF16elt
        elif isinstance(value, six.integer_types) or isinstance(value, six.string_types):
            self.coeffs = [self.field.basefield(value), self.field.basefield(0)]
        elif isinstance(value, (list, tuple,)):
            self.coeffs = [self.field.basefield(thecoeff) for thecoeff in value[:min(2,len(value))]] + [self.field.basefield(0) for i in range(min(2,len(value)), 2)]
        elif (value in self.field.basefield):      # Overload coeffring elt --> constant poly
            self.coeffs = [value, self.field.basefield(0)]
        else: raise ValueError("A GF16elt object cannot be constructed from input \'{0:}\' of type {1:}".format(value,type(value)))

    def __eq__(self, other):  # Implement for both Python2 & 3 with overloading
        if isinstance(other, six.integer_types) or isinstance(other, six.string_types) or isinstance(other, (GF8elt,)) or isinstance(other, (list, tuple,)):
            otherval = self.field(other)
        elif isinstance(other, (GF16elt,)): otherval = other
        else: raise ValueError("Cannot compare equality of a GF16elt object with \'{0:}\' of type {1:}".format(other,type(other)))
        return self.coeffs == otherval.coeffs

    def __ne__(self, other):
        return not self.__eq__(other)

    ######################## Format Operators #################################

    def __format__(self, fmtspec):  # Over-ride format conversion
        """Override the format when outputting a GF16 element.
        A default can be set for the field or specified for each output.
        Possible formats are:
            b- list of GF8 coeffs, each in binary
            x- list of GF8 coeffs, each in hex
            p - polynomial w/ coeffs in GF8 (default hex)
            px - polynomial w/ coeffs in GF8 in hex
            pb - polynomial w/ coeffs in GF8 in binary

        Examples:
            >>> a = GF16elt(["ab","cd"])
            >>> format(a)
            '[ab, cd]'
            >>> format(a,'b')
            '[10101011, 11001101]'
            >>> "Hex:{0:x}, Binary:{0:b}, Poly:{0:p}".format(a)
            'Hex:[ab, cd], Binary:[10101011, 11001101], Poly:(ab) + (cd)*z'
            """
        if fmtspec == '': fmtspec = GF16elt.fmtspec  # Default format is hex
        if fmtspec == 'x': return "[{0:x}, {1:x}]".format(self.coeffs[0], self.coeffs[1])
        elif fmtspec == 'b': return "[{0:b}, {1:b}]".format(self.coeffs[0], self.coeffs[1])
        elif (fmtspec == 'p') or (fmtspec == 'px'): return "({0:x}) + ({1:x})*{2:}".format(self.coeffs[0], self.coeffs[1], self.field.var)
        elif fmtspec == 'pb': return "[{0:b}, {1:b}]".format(self.coeffs[0], self.coeffs[1])
        else: raise ValueError("The format string \'{0:}\' doesn't make sense (or isn't implemented) for a GF16elt object".format(fmtspec))

    def __str__(self):
        """over-ride string conversion used by print"""
        return format(self, self.fmtspec)

    def __int__(self):
        """convert to integer"""
        return (self.coeffs[0]).value + ((self.coeffs[1]).value << 8)

    def __index__(self):
        """convert to integer for various uses including bin, hex and oct (Python 2.5+ only)"""
        return (self.coeffs[0]).value + ((self.coeffs[1]).value << 8)

    if six.PY2:  # Overload hex() and oct() (bin() was never backported to Python 2)
        def __hex__(self): return "0x{0:04x}".format(self.__index__())
        def __oct__(self): return oct(self.__index__())

    ######################## Addition Operators ###############################

    def add(self, summand):
        """add elements of GF16elt (overloaded to allow adding integers and lists of integers)"""
        if not isinstance(summand, (GF16elt,)):
            summand = GF16elt(summand)  # __init_ will raise except if needed
        return GF16elt([self.coeffs[0].add(summand.coeffs[0]),  self.coeffs[1].add(summand.coeffs[1])])

    def neg(self):  # Overload "-" unary operator (no sense over GF(2))
        return self

    def sub(self, summand):  # Overload the "-" binary operator
        return self.add(summand)

    ######################## Multiplication Operators #########################

    def mul(self, multand):  # Elementary multiplication in finite fields
        """multiply elements of GF16 (overloaded to allow integers and lists of integers)"""
        if not isinstance(multand, (GF16elt,)):
            multand = GF16elt(multand)  # __init_ will raise except if needed
        # Multiply coeffs as elements of GF8
        thelist = [self.coeffs[0].mul(multand.coeffs[0]), self.coeffs[0].mul(multand.coeffs[1]).add(self.coeffs[1].mul(multand.coeffs[0])), self.coeffs[1].mul(multand.coeffs[1])]
        # And then reduce mod the driving polynomial of GF16
        return GF16elt(GF16elt.__reduceGF16(thelist))

    @staticmethod
    def __reduceGF16(thelist):  # Value 3-long list of GF8elt values
        return [thelist[0].add(thelist[2].mul(GF16.m)), thelist[1].add(thelist[2])]

    ######################## Division Operators ###############################

    def inv(self):
        """inverse of element in GF16"""
        if (self.coeffs[0].value == 0) and (self.coeffs[1].value == 0): raise ZeroDivisionError("Attempting to invert zero element of GF16")
        # (uy + v)^(-1) = ud^(-1)y + (u + v)d(-1), where d = (u + v)v + mu^2
        d = (self.coeffs[1].add(self.coeffs[0])).mul(self.coeffs[0]).add(GF16.m.mul(self.coeffs[1].mul(self.coeffs[1])))
        dinv = d.inv()   # Invert in GF8
        return GF16elt([(self.coeffs[0].add(self.coeffs[1])).mul(dinv), self.coeffs[1].mul(dinv)])

    def div(self, divisor):
        """divide elements of GF8"""
        if not isinstance(divisor, (GF16elt,)):
            divisor = GF16elt(divisor)  # __init_ will raise except if needed
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

def fit(thepoints, thefield=None):  # Lagrange Interpolation
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
