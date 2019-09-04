# KMIP-SplitKey
Python (and maybe later Rust) implementation of Shamir Secret Sharing, as specified in the KMIP v2.0 protocol

Current status: ver 0.2, 4 Sept 2019:
   * Basic GFp and GF8 functionality working
   * Python 2 broken by Singleton implementation - will fix
   
Plans:
   * Fix Python 2 use (why?) and clean up shamirshare.py
   * Rewrite and tighten up as shamirshare2.py
   * Rewrite in a more conventional language (Rust maybe? Probably not C.  Not COBOL, so don't ask)
   
The current code (shamirshare.py) works, but is utterly Baroque (good for music, less so for code).
The planned rewrite will remove functions not needed for Shamir sharing, remove most operator overloading
and as much coercion code as possible - all things which would be hard to port and prone to bugs.
