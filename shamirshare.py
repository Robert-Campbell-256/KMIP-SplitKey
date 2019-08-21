######################################################################################
# SHAMIRSHARE.py
# The Shamir Key Share scheme, implemented over the finite fields
# GF8 (as featured in AES) and GF16, implemented as a quadratic extension of GF8
# Implementing the 8-bit (later 16-bit, and eventually prime field) Shamir sharing
# mechanism as specified in the KMIP v2.0 protocol.
# Author: Robert Campbell, <r.campbel.256@gmail.com>
# Date: 21 Aug 2019
# Version 0.11
# License: Simplified BSD (see details at bottom)
######################################################################################

"""Code to perform a Shamir Secret Sharing split of a secret, as called for in KMIP v2.0.
Possible ground fields include:
    GF(2^8) - as used by GF8AES
    GF(2^16) - a quadratic extension of the first (not yet implemented)
    GF(p) - for a specified prime p (not yet implemented)
Usage:  Implement a 3-of-7 KeySplit over GF(2^8)
        >>> from shamirshare import *
        >>> GF8x = PolyFieldUniv()                        # Uses default field GF(2^8)
        ################### Create a new key/secret and split it
        >>> [(i,"{0:02x}".format(random.randint(0,256))) for i in range(1,4)] # Choose random splits
            [(1, '45'), (2, '41'), (3, 'c3')]
        >>> pfit = GF8x.fit(((1, '45'), (2, '41'), (3, 'c3'))); format(pfit)
            '[c7, 34, b6, ]'
        # So the polynomial is ('c7' + '34'*x + 'c3'*x^2), and the split secret is pfit(0) = 'c7'
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
    """


__version__ = '0.11' # Format specified in Python PEP 396
Version = 'shamirshare.py, version ' + __version__ + ', 21 Aug, 2019, by Robert Campbell, <r.campbel.256@gmail.com>'

import random
import sys     # Check Python2 or Python3

def isStrType(x):
    if sys.version_info < (3,): return isinstance(x,(basestring,))
    else: return isinstance(x,(str,))

def isIntType(x):
    if sys.version_info < (3,): return isinstance(x,(int, long,))
    else: return isinstance(x,(int,))

def isListType(x):    # List or Tuple: [1,2] or (1,2)
    return isinstance(x,(list, tuple,))

############################# Class GF8AESelt #######################################
# Class GF8AESelt
# Elements of the finite field GF8AES = GF(2^8) = GF(2)[x]/<x^8 + x^4 + x^3 + x + 1>,
#   with the driving (non-primitive) primitive polynomial x^8 + x^4 + x^3 + x + 1, aka "1b",
#   the representation of GF(2^8) used in the construction of the AES block cipher.
#####################################################################################

class GF8AESelt(object):
    """An element of GF(2^8) as represented in AES (driving polynomial x^8 + x^4 + x^3 + x + 1, aka "1b")
    Usage:
        >>> from shamirshare import *
        >>> a = GF8AESelt(123)              # Note that decimal '123' is hex 0x7b
        >>> a                               # Full representation
            <GF8AESelt object at 0x7f8daa662e80>
        >>> "{0:x}".format(a)               # Hex format
            '7b'
        >>> b = GF8AESelt('f5')
        >>> "{0:b}".format(a+b)             # Add, output binary: 0x7b xor 0xf5 = 0x8e = 0b10001110
            '10001110'
    """

    fmtspec = 'x'  # Default format for GF8 is two hex digits

    def __init__(self, value):
        if isinstance(value,(GF8AESelt,)): self.value = value.value # strip redundant GF8AESelt
        if isinstance(value, (int,)): self.value = value
        elif isStrType(value): self.value = int(value,16) # For the moment, assume hex

    def __eq__(self,other): # Implement for both Python2 and Python3 with overloading
        if isIntType(other): otherval = other
        elif isStrType(other): otherval = int(other,16)
        elif isinstance(other,(GF8AESelt,)): otherval = other.value
        return self.value == otherval

    def __ne__(self,other): # Implement for both Python2 and Python3 with overloading
        if isIntType(other): otherval = other
        elif isStrType(other): otherval = int(other,16)
        elif isinstance(other,(GF8AESelt,)): otherval = other.value
        return self.value != otherval

    ######################## Format Operators ########################################

    def __format__(self,fmtspec):  # Over-ride format conversion
        """Override the format when outputting a GF8AES element.
        A default can be set for the field is defined or it can be specified for each output.
        Possible formats are:
            b- coefficients as a binary integer
            x- coefficients as a hex integer
        Example:
            >>> a = GF8AESelt([1,1,0,1,1,1])
            >>> "{0:x}".format(a)
            '37'
            >>> "{0:b}".format(a)
            '00110111'"""
        if fmtspec == '': fmtspec = GF8AESelt.fmtspec  # Default format is hex
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
        def __oct__(self): return hex(self.__index__())

    ######################## Addition Operators ######################################

    def add(self,summand):
        """add elements of GF8AESelt (overloaded to allow adding integers and lists of integers)"""
        return GF8AESelt(self.value ^ GF8AESelt(summand.value).value)

    def __add__(self,summand):   # Overload the "+" operator
        if isinstance(summand,(int,)) or isStrType(summand): # Coerce if adding integer or string and GF8AESelt
            return self.add(GF8AESelt(summand))
        elif isinstance(summand,(GF8AESelt,)):
            return self.add(summand)
        elif isinstance(summand,(PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return summand.__add__(self)
        else: raise NotImplementedError("Can't add GF8AESelt object to {0:} object".format(type(summand)))

    def __radd__(self,summand):  # Overload the "+" operator when first addend can be coerced to GF8AESelt
        return self.__add__(summand)  # Because addition is commutative

    def __iadd__(self,summand): # Overload the "+=" operator
        self = self + summand
        return self

    def __neg__(self):  # Overload the "-" unary operator (makes no sense over GF(2) - true)
        return self

    def __sub__(self,summand):  # Overload the "-" binary operator
        return self.__add__(summand)

    def __isub__(self,summand): # Overload the "-=" operator
        self = self + summand
        return self

    ######################## Multiplication Operators ################################

    def mul(self,multand):  # Elementary multiplication in finite fields
        """multiply elements of GF8AES (overloaded to allow integers and lists of integers)"""
        amult = self.value     # Pull it out of the GF8AESelt structure
        bmult = multand.value  # Pull it out of the GF8AESelt structure
        thenum = 0
        # Multiply as binary polynomials
        for i in range(8): thenum ^= ((bmult<<i) if ((amult >> i) & 0x01) == 1 else 0)
        # And then reduce mod the driving polynomial of GF8AES
        return GF8AESelt(GF8AESelt.__reducegf8aes(thenum))

    def __mul__(self,multip):  # Overload the "*" operator
        if isinstance(multip,(int,)) or isStrType(multip): # Coerce if multiplying integer or string and GF8AESelt
            return self.mul(GF8AESelt(multip))
        elif isinstance(multip,(GF8AESelt,)):
            return self.mul(multip)
        elif isinstance(multip,(PolyFieldUnivElt,)):        # Bit of a hack for operator overload precedence
            return multip.__mul__(self)
        else: raise NotImplementedError("Can't multiply GF8AESelt object with {0:} object".format(type(multip)))

    def __rmul__(self,multip):  # Overload the "*" operator when first multiplicand can be coerced to GF8AESelt
        return self.__mul__(multip)  # Because multiplication is commutative

    def __imul__(self,multip): # Overload the "*=" operator
        self = self * multip
        return self

    @staticmethod
    def __reducegf8aes(thevalue): # Value is integer in range [0,2^16-1]
        reductable = (0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f)
        feedback = 0
        for i in range(8,16): feedback ^= (reductable[i-8] if (((thevalue >> i) & 0x01) == 1)  else 0)
        return ((thevalue & 0xff) ^ feedback)

    ######################## Division Operators ######################################

    # Table based inverse (well, actually pseudo-inverse, as 00-->00)
    __gf8aesinv = {
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
        """inverse of element in GF8AES"""
        if (self.value == 0): raise ZeroDivisionError("Attempting to invert zero element of GF8AES")
        # Tableized (lazy solution for a small field, better solution would be xgcd
        return GF8AESelt(GF8AESelt.__gf8aesinv[str(self)])

    def div(self,divisor):
        """divide elements of GF8AES"""
        return self * divisor.inv()

    def __div__(self,divisor):  # Overload the "/" operator in Python2
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self * divisor.inv()

    def __truediv__(self,divisor):  # Overload the "/" operator in Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self * divisor.inv()

    # As GF8AES is a field, there is no real need for floordiv, but include it
    # as someone will try "//" in any event - if only in error

    def __floordiv__(self,divisor):  # Overload the "//" operator in Python2 and Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self * divisor.inv()

    def __rdiv__(self,dividend):
        if isinstance(dividend,(int,)) or isStrType(dividend): # Coerce if dividing integer or string
            dividend = GF8AESelt(dividend)
        return dividend * self.inv()

    def __rtruediv__(self,dividend):  # Overload the "/" operator in Python3
        if isinstance(dividend,(int,)) or isStrType(dividend): # Coerce if dividing by integer or string
            dividend = GF8AESelt(dividend)
        return dividend * self.inv()

    def __rfloordiv__(self,dividend):  # Overload the "//" operator in Python2 and Python3
        if isinstance(dividend,(int,)) or isStrType(dividend): # Coerce if dividing by integer or string
            dividend = GF8AESelt(dividend)
        return dividend * self.inv()

    def __idiv__(self,divisor):  # Overload the "/=" operator in Python2
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self.div(divisor)

    def __ifloordiv__(self,divisor):  # Overload the "//=" operator
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self.div(divisor)

    def __itruediv__(self,divisor):  # Overload the "//=" operator in Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = GF8AESelt(divisor)
        return self.div(divisor)

############################# Class PolyFieldUniv ###################################
# Class PolyFieldUniv
# A univariable polynomial ring over a specified field of coefficients.
#   A simple container class for PolyFieldUnivElt objects.
#####################################################################################

class PolyFieldUniv(object):
    """Polynomial Ring with a single variable over a specified field of coefficients.
    Usage:
        >>> from shamirshare import *
        >>> GF8x = shamirshare.PolyFieldUniv()         # Default GF8AESelt coeffring
        >>> p3 = shamirshare.PolyFieldUnivElt(GF8x,[1,2,3])
        >>> format(p3)
        '[01, 02, 03, ]'
        """

    def __init__(self, coeffring=type(GF8AESelt(0)), var='x', fmtspec="l"):
        self.coeffring = coeffring       # Set the default coefficient ring (well, actually field)
        self.var = var                   # Used by polynomial format output
        self.fmtspec = fmtspec           # p=polynomial; c=coeffsonly; l=list of coeffs

    def __call__(self,elts):  # Coerce constant or array of coeffs as elt of poly ring
        if isinstance(elts,PolyFieldUnivElt): # Handle unnecessary coercion
            return elts
        elif isListType(elts):              # List or Sequence
            return PolyFieldUnivElt(self,list(map(self.coeffring,elts)))
        elif isIntType(elts) or isStrType(elts):       # Overload int/string --> constant poly
            self.coeffs = [self.coeffring(elts)]
        else:
            return PolyFieldUnivElt(self,[self.coeffring(elts)]) # Coerce coeff as constant poly

    def fit(self,thepoints):  # Lagrange Interpolation
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
    """An element of the ring of polynomails with coefficients in GF(2^8), GF(2^16) or a
       prime field.
    Usage:
        >>> from shamirshare import *
        >>> GF8x = PolyFieldUniv()   # Polynomial Ring: default GF8AESelt coeffs
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
        if isinstance(coeffs,(PolyFieldUnivElt,)): self.coeffs = [self.polyring.coeffring(thecoeff) for thecoeff in coeffs.coeffs]
        elif isinstance(coeffs,(self.polyring.coeffring,)):       # Overload coeffring elt --> constant poly
            self.coeffs = [coeffs]
        elif isIntType(coeffs) or isStrType(coeffs):       # Overload int/string --> constant poly
            self.coeffs = [self.polyring.coeffring(coeffs)]
        elif isListType(coeffs):                        # Overload list --> poly
            coeffs = PolyFieldUnivElt.__trimlist__(coeffs)               # Remove trailing (high order) zeros
            self.coeffs = [self.polyring.coeffring(thecoeff) for thecoeff in coeffs]

    @staticmethod
    def __trimlist__(thelist):  # Remove trailing (high order) zeros in coeff lists
        for x in reversed(thelist):
            if x == 0:  # Rely on overloading of __eq__ for coefficient ring
                del thelist[-1:]
            else:
                break
        return thelist

    def __eq__(self,other): # Implement for both Python2 and Python3 with overloading
        if isIntType(other) or isStrType(other) or isListType(other) or isinstance(other,(self.polyring.coeffring,)):
            otherpoly = PolyFieldUnivElt(self.polyring,other)
        else: otherpoly = other
        return self.coeffs == otherpoly.coeffs

    def __ne__(self,other): # Implement for both Python2 and Python3 with overloading
        if isIntType(other) or isStrType(other) or isListType(other) or isinstance(other,(self.polyring.coeffring,)):
            otherpoly = PolyFieldUnivElt(self.polyring,other)
        else: otherpoly = other
        return self.coeffs == otherpoly.coeffs

    ######################## Format Operators ########################################

    def __format__(self,fmtspec):  # Over-ride format conversion
        """Override the format when outputting a PolyFieldUnivElt element.
        Possible formats are:
            l - list of coefficients
            p - polynomial format with specified variable
        """
        if fmtspec == '': fmtspec = 'l'  # Default format is list
        if fmtspec == 'l': return "["+"".join([(format(thecoeff)+", ") for thecoeff in self.coeffs])+"]"
        if fmtspec == 'p': raise NotImplementedError("polynomial format for PolyFieldUnivarelt is not yet implemented")

    def __str__(self):
        """over-ride string conversion used by print"""
        return '{0:l}'.format(self)

    ######################## Addition Operators ######################################

    @staticmethod
    def __addlists__(list1,list2):
        returnlist = [((list1[i] if i<len(list1) else 0) + (list2[i] if i<len(list2) else 0)) for i in range(max(len(list1),len(list2)))]
        return returnlist

    def add(self,summand):
        """add elements of PolyFieldUnivElt (overloaded to allow adding integers and lists of integers)"""
        thecoeffs = PolyFieldUnivElt.__addlists__(self.coeffs,summand.coeffs)
        thecoeffs = PolyFieldUnivElt.__trimlist__(thecoeffs)
        return PolyFieldUnivElt(self.polyring,thecoeffs)

    def __add__(self,summand):   # Overload the "+" operator
        if isIntType(summand) or isStrType(summand) or isListType(summand): # Coerce if adding integer, string or list
            return self.add(PolyFieldUnivElt(self.polyring,summand))
        else:
            return self.add(summand)

    def __radd__(self,summand):  # Overload the "+" operator when first addend can be coerced to ring of coeffs
        return self.__add__(summand)  # Because addition is commutative

    def __iadd__(self,summand): # Overload the "+=" operator
        self = self + summand
        return self

    def __neg__(self):  # Overload the "-" unary operator (makes no sense over GF(2) - true)
        return PolyFieldUnivElt(self.polyring,[-thecoeff for thecoeff in self.coeffs])

    def __sub__(self,summand):  # Overload the "-" binary operator
        return self.__add__(-summand)

    def __isub__(self,summand): # Overload the "-=" operator
        self = self - summand
        return self

    ######################## Multiplication Operators ################################

    def mul(self,multand):  # Elementary multiplication of polynomials
        """multiply polynomials (overloaded to allow integers and lists of integers)"""
        polydeg = len(self.coeffs)+len(multand.coeffs)-2
        thelist = [self.polyring.coeffring(0) for i in range(polydeg+1)]
        for d in range(polydeg+1):
            thelist[d] = sum(self.coeffs[d-i]*multand.coeffs[i] for i in range(max(0,d-len(self.coeffs)+1),min(d+1,len(multand.coeffs))))
        return PolyFieldUnivElt(self.polyring,thelist)

    def __mul__(self,multand):  # Overload the "*" operator
        if isListType(multand):
            # Coerce if multiplying list, elts are coerceable into coeff ring, thought of as poly coeff list
            return self.mul(PolyFieldUnivElt(self.polyring,[self.polyring.coeffring(thecoeff) for thecoeff in multand]))
        elif isIntType(multand) or isinstance(multand,self.polyring.coeffring):
            # Coerce if multiplying integer or elt of coeff field (thought of as constant, ie deg 0, polynomial)
            return self.mul(PolyFieldUnivElt(self.polyring,multand))
        else: # Normal case, multiply by PolynomialFieldUnivarElt
            return self.mul(multand)

    def __rmul__(self,multand):  # Overload the "*" operator
        return self.__mul__(multand)

    def __imul__(self,multand): # Overload the "*=" operator
        self = self * multand
        return self

    ######################## Division Operators ######################################

    # Not needed (I think) for Shamir SS
    # BUT ... Do need to implement division of polynomial by constant

    def div(self,divisor):  # Elementary division of polynomials (but only by constants)
        """divide polynomials - for shamirshare only need case of dividing by constants
        (overloaded to allow integers and lists of integers)
        As the coefficient ring (self.polyring.coeffring) is assumed to be a field, we combine floordiv and truediv functions."""
        if (divisor == 0): raise ZeroDivisionError("Attempting to divide polynomial by zero element of coefficient ring")
        return PolyFieldUnivElt(self.polyring,[self.coeffs[i]/divisor for i in range(len(self.coeffs))])

    def __div__(self,divisor):  # Overload the "/" operator in Python2
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.div(divisor)

    def __truediv__(self,divisor):  # Overload the "/" operator in Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.div(divisor)

    def __floordiv__(self,divisor):  # Overload the "//" operator in Python2 and Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.div(divisor)

    def idiv(self,divisor):  # In-place division of polynomials (but only by constants)
        """in-place divide polynomials - for shamirshare only need case of dividing by constants
        (overloaded to allow integers and lists of integers)
        As the coefficient ring (self.polyring.coeffring) is assumed to be a field, we combine floordiv and truediv functions."""
        if (divisor == 0): raise ZeroDivisionError("Attempting to divide polynomial by zero element of coefficient ring")
        for i in range(len(self.coeffs)): self.coeffs[i] /= divisor
        return self

    def __idiv__(self,divisor):  # Overload the "/=" operator in Python2
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.idiv(divisor)

    def __ifloordiv__(self,divisor):  # Overload the "//=" operator
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.idiv(divisor)

    def __itruediv__(self,divisor):  # Overload the "//=" operator in Python3
        if isinstance(divisor,(int,)) or isStrType(divisor): # Coerce if dividing by integer or string
            divisor = self.polyring.coeffring(divisor)
        return self.idiv(divisor)

    ######################## Other Operators #########################################

    def eval(self,xvalue):  # Evaluate a function at a given value using Horder's Rule
        polydeg = len(self.coeffs)-1
        theval = self.coeffs[polydeg]
        for theindex in range(polydeg-1,-1,-1):
            theval = theval*xvalue + self.coeffs[theindex]
        return theval  # Note: Value returned is in polyring.coeffring, not the polynomial ring

    # Allow usage "p1(123)" to evaluate polynomial p1 at the value 123
    def __call__(self,value):
        return self.eval(value)

# Thoughts and Bugs:
#   - Should class(elt) be a deep copy or should it just return elt?
#   - Implement GF8AESelt.random() to get random elements
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
#       the documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY EXPRESS
# OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
# SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
############################################################################
