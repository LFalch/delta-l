//! Crate for using Delta-L encryption
#![warn(missing_docs, clippy::all)]

pub use self::DecryptionError::{Io, InvalidHeader, ChecksumMismatch};

use std::hash::Hasher;

use siphasher::sip::SipHasher;

use std::fmt;
use std::io;
use std::io::{Read, Write};

use std::error::Error;

/// Convenient `Result` type for `DecryptionError`
pub type Result<T> = ::std::result::Result<T, DecryptionError>;

/// Wrapper for errors that can occur during decryption
#[derive(Debug)]
pub enum DecryptionError{
    /// Errors that are just plain IO errors
    Io(io::Error),
    /// Invalid header error
    InvalidHeader,
    /// Checksum mismatch error
    ChecksumMismatch(Vec<u8>),
}

impl fmt::Display for DecryptionError{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
        match *self{
            Io(ref err)          => err.fmt(f),
            InvalidHeader        => write!(f, "The header was not valid."),
            ChecksumMismatch(..) => write!(f, "The checksum of the output file did not match the checksum in the header."),
        }
    }
}

impl Error for DecryptionError{
    fn description(&self) -> &str{
        match *self{
            Io(ref err)          => err.description(),
            InvalidHeader        => "header wasn't valid",
            ChecksumMismatch(..) => "checksum of output file didn't match header checksum",
        }
    }
}

impl From<io::Error> for DecryptionError{
    fn from(e: io::Error) -> DecryptionError{
        DecryptionError::Io(e)
    }
}

/// Provides interface for Delta-L encryption/decryption
#[derive(Debug, Copy, Clone)]
pub struct DeltaL{
    passhash: [u8; 8]
}

impl Default for DeltaL {
    fn default() -> Self {
        DeltaL{
            passhash: [0; 8]
        }
    }
}

impl DeltaL{
    /// Creates a `DeltaL` instance
    pub fn new() -> DeltaL{
        Self::default()
    }

    /// Sets the passphrase for the `DeltaL`
    pub fn set_passphrase(&mut self, passphrase: &str){
        self.passhash = hash_as_array(passphrase.as_bytes())
    }

    /// Encodes
    pub fn encode<R: Read, W: Write>(self, src: &mut R, dest: &mut W, checksum: bool) -> io::Result<()>{
        let mut buffer = Vec::<u8>::new();

        src.read_to_end(&mut buffer)?;

        // Do header related things

        // Makes delta symbol: Δ
        dest.write_all(&[206, 148])?;

        // Capital L if checksum is enabled, lowercase if disabled
        if checksum {
            dest.write_all(b"L\n")?;

            dest.write_all(&hash_as_array(&buffer))?;
        } else {
            dest.write_all(b"l\n")?;
        }

        let mut last: u8 = 0;

        let coded_buffer: Vec<_> = buffer
            .into_iter()
            .enumerate()
            .map(|(i, b)|{
                // Add last byte when encrypting
                let ret = b.wrapping_add(self.passhash[i & 7]).wrapping_add(last);
                last = b;
                ret
            }).collect();

        dest.write_all(&coded_buffer)?;
        dest.flush()?;

        Ok(())
    }

    /// Decodes
    pub fn decode<R: Read, W: Write>(self, src: &mut R, dest: &mut W) -> Result<()>{
        let mut buffer = Vec::<u8>::new();

        src.read_to_end(&mut buffer)?;

        let skip;
        let mut checksum: Option<[u8; 8]> = None;

        // Do header related things
        if buffer.len() > 3 && (buffer[0], buffer[1], buffer[3]) == (206, 148, 10) {
            match buffer[2]{
                b'L' if buffer.len() > 11 => {
                    checksum = Some(slice_to_array(&buffer[4..12]));
                    skip = 12;
                },
                b'l' => {
                    skip = 4;
                },
                _ => return Err(InvalidHeader)
            }
        }else{
            return Err(InvalidHeader)
        }

        let mut last: u8 = 0;

        let coded_buffer: Vec<u8> = buffer
            .into_iter()
            .skip(skip)
            .enumerate()
            .map(|(i, b)| {
                // Subtract byte last read when decrypting
                last = b.wrapping_sub(self.passhash[i & 7]).wrapping_sub(last);
                last
            })
            .collect();

        if let Some(check) = checksum {
            if check != hash_as_array(&coded_buffer){
                return Err(ChecksumMismatch(coded_buffer))
            }
        }

        dest.write_all(&coded_buffer)?;
        dest.flush()?;

        Ok(())
    }
}

#[inline]
fn slice_to_array(slice: &[u8]) -> [u8; 8]{
    [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]
}

fn hash_as_array(to_be_hashed: &[u8]) -> [u8; 8]{
    let mut siphasher = SipHasher::new();
    siphasher.write(to_be_hashed);

    unsafe {::std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())}
}
