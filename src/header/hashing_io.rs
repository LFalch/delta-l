use std::io::{Result, Read, Write};
use std::hash::Hasher;

use siphasher::sip::SipHasher;

#[derive(Debug, Clone)]
pub struct HashingWrite<T: Write> {
    hasher: SipHasher,
    inner: T,
}

impl<T: Write> HashingWrite<T> {
    #[inline]
    pub fn new(writer: T) -> Self {
        Self {
            inner: writer,
            hasher: SipHasher::new(),
        }
    }
    #[inline]
    pub fn into_inner(self) -> (T, u64) {
        let Self{inner, ..} = self;
        (inner, self.hasher.finish())
    }
}
impl<T: Write> Write for HashingWrite<T> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.write(&buf[..n]);

        Ok(n)
    }
    #[inline]
    fn flush(&mut self) -> Result<()> {
        self.inner.flush()
    }
}

#[derive(Debug, Clone)]
pub struct HashingRead<T: Read> {
    hasher: SipHasher,
    inner: T,
}

impl<T: Read> HashingRead<T> {
    #[inline]
    pub fn new(reader: T) -> Self {
        Self {
            inner: reader,
            hasher: SipHasher::new(),
        }
    }
    #[inline]
    pub fn into_inner(self) -> (T, u64) {
        let Self{inner, ..} = self;
        (inner, self.hasher.finish())
    }
}
impl<T: Read> Read for HashingRead<T> {
    #[inline]
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.write(&buf[..n]);

        Ok(n)
    }
}
