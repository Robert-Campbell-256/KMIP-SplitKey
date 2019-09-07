# KMIP-SplitKey
Python (and maybe later Rust) implementation of Shamir Secret Sharing, as specified in the KMIP v2.0 protocol

Current status: ver 0.21, 7 Sept 2019:
   * Basic GFp and GF8 functionality working (need to implement GF16)
   * Python 2 Singleton issue fixed
   
Plans:
   * Clean up shamirshare.py and add support for GF16
   * Rewrite and tighten up as shamirshare2.py
   * Rewrite in a more conventional language (Rust maybe? Probably not C.  Not COBOL, so don't ask)
   
The current code (shamirshare.py) works, but is utterly Baroque (good for music, less so for code).
The planned rewrite will remove functions not needed for Shamir sharing, remove most operator overloading
and as much coercion code as possible - all things which would be hard to port and prone to bugs.
