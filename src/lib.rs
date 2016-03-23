//! Crate for using Delta-L encryption
#![warn(missing_docs)]
pub use self::Mode::{Encrypt, Decrypt};
pub use self::DeltaLError::{Io, InvalidHeader, ChecksumMismatch};

use std::hash::{Hasher, SipHasher};

use std::fmt;
use std::io;
use std::io::{Read, Write};

use std::fs::File;
use std::path::Path;

use std::error::Error;

/// Convenient `Result` type for `DeltaLError`
pub type Result<T> = ::std::result::Result<T, DeltaLError>;

/// Describes errors that can occur during encryption and decryption
#[derive(Debug)]
pub enum DeltaLError{
    /// Errors that are just plain IO errors
    Io(io::Error),
    /// Invalid header error
    InvalidHeader,
    /// Checksum mismatch error
    ChecksumMismatch(Vec<u8>),
}

impl fmt::Display for DeltaLError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        match *self{
            Io(ref err)          => err.fmt(f),
            InvalidHeader        => write!(f, "The header was not valid."),
            ChecksumMismatch(..) => write!(f, "The checksum of the output file did not match the checksum in the header."),
        }
    }
}

impl Error for DeltaLError{
    fn description(&self) -> &str{
        match *self{
            Io(ref err)          => err.description(),
            InvalidHeader        => "header wasn't valid",
            ChecksumMismatch(..) => "checksum of output file didn't match header checksum",
        }
    }
}

impl From<io::Error> for DeltaLError{
    fn from(e: io::Error) -> DeltaLError{
        DeltaLError::Io(e)
    }
}

/// Specifies whether to encrypt or decrypt
#[derive(Debug, Copy, Clone)]
pub enum Mode{
    /// Specifies that we're encrypting
    Encrypt{
        /// Specifies whether to enable checksum verification
        checksum: bool
    },
    /// Specifies that we're decrypting
    Decrypt,
}

/// Provides interface for Delta-L encryption/decryption
#[derive(Debug, Copy, Clone)]
pub struct DeltaL{
    mode    : Mode,
    passhash: [u8; 8],
}

impl DeltaL{
    /// Creates a `DeltaL` instance
    pub fn new(mode: Mode) -> DeltaL{
        DeltaL{
            mode     : mode,
            passhash: [0; 8],
        }
    }

    /// Enables/disables checksum, if mode is `Encrypt`
    pub fn set_checksum(&mut self, checksum_flag: bool) -> bool{
        if let Encrypt{ref mut checksum} = self.mode{
            *checksum = checksum_flag;
            true
        }else{
            false
        }
    }

    /// Sets the passphrase for the `DeltaL`
    pub fn set_passphrase(&mut self, passphrase: &str){
        self.passhash = hash_as_array(passphrase.as_bytes())
    }

    fn offset(&self, (i, b): (usize, u8)) -> u8{
        if self.is_mode_encrypt(){
            b.wrapping_add(self.passhash[i % 8])
        }else{
            b.wrapping_sub(self.passhash[i % 8])
        }
    }

    /// Returns ".delta" for encryption and ".dec" for decryption
    pub fn get_mode_standard_extension(&self) -> &'static str{
        match self.mode{
            Encrypt{..} => ".delta",
            Decrypt     => ".dec",
        }
    }

    /// Returns whether the mode is `Encrypt`
    pub fn is_mode_encrypt(&self) -> bool{
        match self.mode{
            Encrypt{..} => true,
            _           => false,
        }
    }

    /// Codes the file in from_path to the file in to_path
    pub fn execute<P: AsRef<Path>>(&self, from_path: P) -> Result<Vec<u8>>{
        let mut f = try!(File::open(&from_path));
        let mut buffer = Vec::<u8>::new();

        try!(f.read_to_end(&mut buffer));

        let mut coded_buffer: Vec<u8>;

        let mut skip = 0;
        let mut checksum: Option<[u8; 8]> = None;

        // Do header related things
        if let Encrypt{checksum} = self.mode {
            coded_buffer = Vec::with_capacity(buffer.len());

            // Makes delta symbol: Δ
            coded_buffer.push(206);
            coded_buffer.push(148);

            // Capital L (76) if checksum is enabled, lowercase (108) if disabled
            if checksum {
                coded_buffer.reserve(12);

                coded_buffer.push(76);
                coded_buffer.push(10); // Push a newline

                coded_buffer.extend_from_slice(&hash_as_array(&buffer));
            } else {
                coded_buffer.reserve(4);

                coded_buffer.push(108);
                coded_buffer.push(10); // Push a newline
            }
        } else { // if `Decrypt`
            if buffer.len() > 3 && (buffer[0], buffer[1], buffer[3]) == (206, 148, 10) {
                match buffer[2]{
                    76 if buffer.len() > 11 => {
                        checksum = Some(slice_to_array(&buffer[4..12]));
                        skip = 12;
                    },
                    108 => {
                        skip = 4;
                    },
                    _ => return Err(InvalidHeader)
                }
                coded_buffer = Vec::with_capacity(buffer.len() - skip);
            }else{
                return Err(InvalidHeader)
            }
        }

        {
            let mut last: u8 = 0;

            let mut diff: Box<FnMut(u8) -> u8> = match self.mode {
                Encrypt{..} => Box::new(|b: u8| {
                    // Add last byte when encrypting
                    let ret = b.wrapping_add(last);
                    last = b;
                    ret
                }),
                Decrypt => Box::new(|b: u8| {
                    // Subtract byte last read when decrypting
                    last = b.wrapping_sub(last);
                    last
                })
            };

            coded_buffer.append(&mut buffer.into_iter()
                .skip(skip)
                .enumerate()
                .map(|x| diff(self.offset(x)))
                .collect());
        }

        if let Some(check) = checksum {
            if check != hash_as_array(&coded_buffer){
                return Err(ChecksumMismatch(coded_buffer))
            }
        }

        Ok(coded_buffer)
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
