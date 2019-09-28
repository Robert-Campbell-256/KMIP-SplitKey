# KMIP-SplitKey
Python (and maybe later Rust, maybe even Go) implementation of Shamir Secret Sharing, as specified in the KMIP v2.0 protocol

## Plans and Progress

Plans:
   * Rewrite and tighten up shamirshare.py as shamirshare2.py (done)
   * Rewrite in a more conventional language (Rust maybe? Probably not C.  Not COBOL, so don't ask)
   
The original implementation (shamirshare.py) works, but was utterly Baroque (good for music, less so for code).
The rewrite (shamirshare2.py) removes functions not needed for Shamir sharing, removes most operator overloading
and as much coercion code as possible - all things which will be hard to port to more conventional
languages and are prone to bugs in any language.

## Shamirshare2.py

Current status: ver 0.32, 27 Sept 2019:
   * Minor edits to make the comments doctest friendly

ver 0.31, 25 Sept 2019:
   * Replaced home-rolled Python2/3 compatible functions with six package

ver 0.3, 22 Sept 2019:
   * Implemented GF16

ver 0.2, 21 Sept 2019:
   * Implemented GF8

ver 0.1, 18 Sept 2019:
   * Implemented GFp, fit and eval functions
   * Need to implement GF8 and GF16

## Shamirshare.py

Current status: ver 0.3, 11 Sept 2019:
   * Implemented GF16
   * Essentially done with this verbose version (time to implement in simpler Python, then ...)
   
ver 0.21, 7 Sept 2019:
   * Basic GFp and GF8 functionality working (need to implement GF16)
   * Python 2 Singleton issue fixed
   
...

ver 0.1, 18 Aug 2019:
   * Initial commit
   * Implemented GF8 base field, fit and call (aka eval) functions
   
## Splitting a Secret w/ GF8 or GF16

Normally your secret will be larger than a single 8-bit byte.  Divide the secret into byte-size slices, and split each byte separately over GF8.  For each user the split bytes can themselves be combined to form a larger split.  The same approach can be used for GF16 - splitting the secret into 16-bit slices.

Example - GF8 3-way (i.e. quadratic) split of 32-bit secret (i.e. 4 slices)
```
>>> thesplits = [[[gf8(user), gf8(randint(0,255))] for user in range(1,4)] for slice in range(4)]
>>> [[[format(thesplits[slice][user][0]),format(thesplits[slice][user][1])] for user in range(3)] for slice in range(4)] 
    [
        [['01', 'b2'], ['02', 'd7'], ['03', 'e8']], 
        [['01', 'f0'], ['02', '0e'], ['03', '9e']], 
        [['01', 'ea'], ['02', '7d'], ['03', '28']], 
        [['01', '76'], ['02', 'b8'], ['03', 'b8']]
    ]
```
User #1 has array of secrets ```['b2','f0','ea','76']```, user #2 has ```['d7','0e','7d','b8']```, etc.
```
>>> pfit0 = fit(thesplits[0]); list(map(format,pfit0))
    ['8d', '31', '0e']
```
So first byte (slice) is split by polynomial ```8d + 31*x + 0e*x^2```, and has secret value '8d'. The total 32-bit secret is the array ```['8d','60','bf','76']```.
```
>>> pfit = [fit(thesplits[slice]) for slice in range(4)] 
>>> list(map(format,[pfit[slice][0] for slice in range(4)]))
    ['8d', '60', 'bf', '76']
```
As usual, a pre-existing secret can be split by making one of the splits for a “user #0”.

