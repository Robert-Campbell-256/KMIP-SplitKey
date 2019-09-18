# KMIP-SplitKey
Python (and maybe later Rust) implementation of Shamir Secret Sharing, as specified in the KMIP v2.0 protocol

## Plans and Progress

Plans:
   * Rewrite and tighten up shamirshare.py as shamirshare2.py
   * Rewrite in a more conventional language (Rust maybe? Probably not C.  Not COBOL, so don't ask)
   
The current code (shamirshare.py) works, but is utterly Baroque (good for music, less so for code).
The planned rewrite will remove functions not needed for Shamir sharing, remove most operator overloading
and as much coercion code as possible - all things which would be hard to port to more conventional
languages and are prone to bugs in any language.

## Shamirshare2.py

Current status: ver 0.1, 18 Sept 2019:
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