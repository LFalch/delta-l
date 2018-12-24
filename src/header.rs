//! Implementations of the Delta L header
//!
//! Usually used for encryption and decryption of files

use byteorder::{LittleEndian, ByteOrder};

use self::Error::{Io, InvalidHeader, ChecksumMismatch};

use std::fmt;
use std::io::{self, Read, Write, Seek, SeekFrom};
use std::error::Error as ErrorTrait;

use crate::{Offset, DeltaWriter, DeltaReader};

/// Result alias for convenience
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

mod hashing_io;

use self::hashing_io::{HashingRead, HashingWrite};

impl fmt::Display for Error{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result{
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

/// Encodes the `src` into `dest` using the **no** checksum header
pub fn encode_no_checksum<O: Offset, R: Read, W: Write>(offsetter: O, src: &mut R, dest: &mut W) -> Result{
    // Write header (Δl\n)
    dest.write_all(b"\xCE\x94l\n")?;
    let mut dest = DeltaWriter::with_offsetter(dest, offsetter);

    io::copy(src, &mut dest)?;
    dest.flush().map_err(Into::into)
}

/// Encodes the `src` into `dest` using the checksum header
pub fn encode_with_checksum<O: Offset, R: Read, W: Write + Seek>(offsetter: O, src: &mut R, dest: &mut W) -> Result{
    // Write header (ΔL\n)
    dest.write_all(b"\xCE\x94L\n")?;
    dest.write_all(b"HASHCODE")?;

    let mut src = HashingRead::new(src);
    let mut dest = DeltaWriter::with_offsetter(dest, offsetter);
    io::copy(&mut src, &mut dest)?;
    dest.flush()?;
    let (_, hash) = src.into_inner();
    let dest = dest.into_inner();

    let mut checksum = [0; 8];
    LittleEndian::write_u64(&mut checksum, hash);

    dest.seek(SeekFrom::Start(4))?;
    dest.write_all(&checksum)?;

    dest.flush().map_err(Into::into)
}

/// Decodes the `src` into `dest` determining whether to check checksum based on header
pub fn decode<O: Offset, R: Read, W: Write>(offsetter: O, src: &mut R, dest: &mut W) -> Result {
    let mut header = [0; 4];
    src.read_exact(&mut header)?;

    if (header[0], header[1], header[3]) == (0xCE, 0x94, b'\n') {
        match header[2] {
            b'L' => {
                let mut cs = [0; 8];
                src.read_exact(&mut cs)?;
                let checksum = LittleEndian::read_u64(&cs);
                decode_with_checksum(offsetter, checksum, src, dest)
            },
            b'l' => decode_no_checksum(offsetter, src, dest),
            _ => Err(InvalidHeader)
        }
    } else {
        Err(InvalidHeader)
    }
}

fn decode_with_checksum<O: Offset, R: Read, W: Write>(offsetter: O, checksum: u64, src: &mut R, dest: &mut W) -> Result {
    let mut src = DeltaReader::with_offsetter(src, offsetter);
    let mut dest = HashingWrite::new(dest);

    io::copy(&mut src, &mut dest)?;
    let (dest, hash) = dest.into_inner();

    if checksum != hash {
        return Err(ChecksumMismatch)
    }

    dest.flush().map_err(Into::into)
}

fn decode_no_checksum<O: Offset, R: Read, W: Write>(offsetter: O, src: &mut R, dest: &mut W) -> Result {
    let mut src = DeltaReader::with_offsetter(src, offsetter);
    io::copy(&mut src, dest)?;
    dest.flush().map_err(Into::into)
}
