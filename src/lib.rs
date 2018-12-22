//! Crate for using Delta-L encryption
#![warn(missing_docs, clippy::all)]

use byteorder::{LittleEndian, ByteOrder};

use std::io::{Result, Write, Read};

use std::hash::Hasher;
use siphasher::sip::SipHasher;

pub mod header;

pub use crate::header::{decode, encode_no_checksum, encode_with_checksum};

/// Offsets for delta-l
pub trait Offset {
    /// Return the next offset
    fn next_offset(&mut self) -> u8;
    /// Turn the state one back, as if it hadn't made that last `next_offset` call
    ///
    /// Does not check whether `next_offset` has ever been called and there are no guarantees
    /// for its state if it's called before any `next_offset` calls
    fn step_back(&mut self);
    /// Reset the state of the offsetter
    fn reset(&mut self);
}

#[derive(Default, Debug, Clone, Copy)]
/// An implementation of [`Offset`] using the sip hash of a string
pub struct PassHashOffsetter {
    pass_hash: [u8; 8],
    index: usize,
}

impl PassHashOffsetter {
    /// Makes a new instance using the given string
    pub fn new(passphrase: &str) -> Self {
        let mut siphasher = SipHasher::new();
        siphasher.write(passphrase.as_bytes());

        let mut pass_hash = [0; 8];
        LittleEndian::write_u64(&mut pass_hash, siphasher.finish());

        Self {
            pass_hash,
            index: 0,
        }
    }
}

impl Offset for PassHashOffsetter {
    #[inline]
    fn next_offset(&mut self) -> u8 {
        let ret = unsafe {*self.pass_hash.get_unchecked(self.index)};
        self.index = (self.index + 1) & 7;
        ret
    }
    #[inline]
    fn step_back(&mut self) {
        self.index = (self.index + 7) & 7;
    }
    #[inline]
    fn reset(&mut self) {
        self.index = 0;
    }
}

/// Returns 0 only
pub struct ZeroOffset;
impl Offset for ZeroOffset {
    #[inline]
    fn next_offset(&mut self) -> u8 {
        0
    }
    #[inline]
    fn step_back(&mut self) { }
    #[inline]
    fn reset(&mut self) { }
}

// TODO Implement `Seek` so that the `last` will be the right value and `offsetter` will have
// the correct state

#[derive(Debug, Clone)]
/// A `Write`r that writes each byte according to the delta encoding
pub struct DeltaWrite<T: Write, O: Offset> {
    last: u8,
    inner: T,
    offsetter: O
}

impl<T: Write> DeltaWrite<T, ZeroOffset> {
    /// Returns a `DeltaWrite` without offsetting
    #[inline]
    pub fn new(inner: T) -> Self {
        Self::with_offsetter(inner, ZeroOffset)
    }
}

impl<T: Write, O: Offset> DeltaWrite<T, O> {
    /// Returns a `DeltaWrite`r with a given `Offsetter`
    #[inline]
    pub fn with_offsetter(inner: T, offsetter: O) -> Self {
        Self {
            inner,
            offsetter,
            last: 0,
        }
    }
    /// Returns a the inner `Write`r
    #[inline]
    pub fn into_inner(self) -> T {
        let Self{inner, ..} = self;
        inner
    }
}

impl<T: Write, O: Offset> Write for DeltaWrite<T, O> {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let mut total_len = 0;
        for &b in buf {
            let byte2write = b.wrapping_add(self.offsetter.next_offset()).wrapping_add(self.last);
            match self.inner.write(&[byte2write])? {
                0 => {
                    self.offsetter.step_back();
                    return Ok(total_len)
                },
                n => total_len += n,
            }
            self.last = b;
        }
        debug_assert_eq!(total_len, buf.len());
        Ok(total_len)
    }
    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        for &b in buf {
            let byte2write = b.wrapping_add(self.offsetter.next_offset()).wrapping_add(self.last);
            self.last = b;
            self.inner.write_all(&[byte2write])?;
        }
        Ok(())
    }
    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Clone)]
/// A `Read`er that reads each byte according to the delta encoding
pub struct DeltaRead<T: Read, O: Offset> {
    last: u8,
    inner: T,
    offsetter: O,
}

impl<T: Read> DeltaRead<T, ZeroOffset> {
    /// Returns a `DeltaRead` without offsetting
    #[inline]
    pub fn new(inner: T) -> Self {
        Self::with_offsetter(inner, ZeroOffset)
    }
}

impl<T: Read, O: Offset> DeltaRead<T, O> {
    /// Returns a `DeltaRead`er with a given `Offsetter`
    #[inline]
    pub fn with_offsetter(inner: T, offsetter: O) -> Self {
        Self {
            inner,
            offsetter,
            last: 0,
        }
    }
    /// Returns a the inner `Read`er
    #[inline]
    pub fn into_inner(self) -> T {
        let Self{inner, ..} = self;
        inner
    }
}

impl<T: Read, O: Offset> Read for DeltaRead<T, O> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.read(buf)?;
        for b in &mut buf[..n] {
            self.last = b.wrapping_sub(self.offsetter.next_offset()).wrapping_sub(self.last);
            *b = self.last;
        }
        Ok(n)
    }
}
