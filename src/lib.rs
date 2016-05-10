//! Crate for using Delta-L encryption
#![warn(missing_docs, clippy::all)]

extern crate byteorder;
use byteorder::{LittleEndian, ByteOrder};

pub use self::Error::{Io, InvalidHeader, ChecksumMismatch};

use std::hash::Hasher;

use siphasher::sip::SipHasher;

use std::fmt;
use std::io::{self, Read, Write};

use std::error::Error as ErrorTrait;

pub type Result = std::result::Result<(), Error>;

/// Wrapper for errors that can occur during decryption
#[derive(Debug)]
pub enum Error{
    /// Errors that are just plain IO errors
    Io(io::Error),
    /// Invalid header error
    InvalidHeader,
    /// Checksum mismatch error
    ChecksumMismatch,
}

impl fmt::Display for Error{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        match *self{
            Io(ref err)      => err.fmt(f),
            InvalidHeader    => write!(f, "The header was not valid."),
            ChecksumMismatch => write!(f, "The checksum of the output file did not match the checksum in the header."),
        }
    }
}

impl ErrorTrait for Error{
    fn description(&self) -> &str{
        match *self{
            Io(ref err)      => err.description(),
            InvalidHeader    => "header wasn't valid",
            ChecksumMismatch => "checksum of output file didn't match header checksum",
        }
    }
}

impl From<io::Error> for Error{
    fn from(e: io::Error) -> Error{
        Error::Io(e)
    }
}

/// Generates a passhash from the given passphrase
#[inline]
pub fn get_passhash(passphrase: &str) -> [u8; 8]{
    let mut siphasher = SipHasher::new();
    siphasher.write(passphrase.as_bytes());

    let mut ret = [0; 8];
    LittleEndian::write_u64(&mut ret, siphasher.finish());
    ret
}

pub fn encode_no_checksum<R: Read, W: Write>(passhash: [u8; 8], src: &mut R, dest: &mut W) -> Result{
    // Write header (Δl\n)
    dest.write_all(b"\xCE\x94l\n")?;

    let mut last: u8 = 0;

    for (i, b) in src.bytes().enumerate(){
        let b = b?;
        dest.write_all(&[b.wrapping_add(passhash[i & 7]).wrapping_add(last)])?;
        last = b;
    }

    dest.flush().map_err(Into::into)
}

pub fn encode_with_checksum<R: Read, W: Write>(passhash: [u8; 8], src: &mut R, dest: &mut W) -> Result{
    // Write header (ΔL\n)
    dest.write_all(b"\xCE\x94L\n")?;

    let mut coded_buffer = Vec::new();
    let mut hasher = SipHasher::new();

    let mut checksum = [0; 8];
    // Write some placeholder bytes for the checksum
    dest.write_all(&checksum)?;

    let mut last: u8 = 0;

    for (i, b) in src.bytes().enumerate(){
        let b = b?;

        dest.write_all(&[b.wrapping_add(passhash[i & 7]).wrapping_add(last)])?;
        hasher.write(&[b]);

        last = b;
    }

    let mut checksum = [0; 8];
    LittleEndian::write_u64(&mut checksum, hasher.finish());

    dest.seek(SeekFrom::Start(4))?;
    dest.write_all(&checksum)?;

    dest.flush().map_err(Into::into)
}

pub fn decode<R: Read, W: Write>(passhash: [u8; 8], src: &mut R, dest: &mut W) -> Result{
    let mut header = [0; 4];
    src.read(&mut header)?;

    let checksum = if (header[0], header[1], header[3]) == (206, 148, 10) {
        match header[2]{
            b'L' => {
                let mut cs = [0; 8];
                src.read_exact(&mut cs)?;
                Some(LittleEndian::read_u64(&cs))
            },
            b'l' => {
                None
            },
            _ => return Err(InvalidHeader)
        }
    }else{
        return Err(InvalidHeader)
    };

    let mut last: u8 = 0;
    let mut hasher = SipHasher::new();

    for (i, b) in src.bytes().enumerate(){
        let b = b?;

        // Subtract byte last read when decrypting
        last = b.wrapping_sub(passhash[i & 7]).wrapping_sub(last);
        dest.write(&[last])?;
        if checksum.is_some(){
            hasher.write(&[last])
        }
    }

    if let Some(c) = checksum {
        if c != hasher.finish(){
            return Err(ChecksumMismatch)
        }
    }

    dest.flush().map_err(Into::into)
}
