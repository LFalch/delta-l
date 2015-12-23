# delta-l [![Build Status](https://travis-ci.org/LFalch/delta-l.svg?branch=master)](https://travis-ci.org/LFalch/delta-l)

Program that can encrypt and decrypt files.

## Quick notes and some history

I don't recommend using this encryption algorithm for anything important (see Flaws) --
This was mostly an interesting idea that came to me, so I made it as a little exercise.

Initially, I actually tried to make this in Java, but that project got very messy
and I abandoned it a long time ago (before I knew of Rust). Then recently, I remembered
that project and thought it would a cool little thing to make in Rust, and here it is.

## The algorithm

Encryption is done by taking each byte and adding with the previous byte
(the first byte will just be the byte itself). The addition allows overflowing,
i.e. it will just wrap.

For example, let's say we have a file with the following bytes (in hex): 20 A3 17 55.
The resulting file would be: 20 E3 7D 25 8B
(Note: this isn't exactly true, since the resulting file also would have a header)

Decryption just does the reverse.

When using a passphrase, the passphrase will be hashed and the hash will
be used as an extra offset on each byte.

## Flaws
- This is very fast and should therefore be very easy to break, when using checksum.
