//! Crate for using Delta-L encryption
#![warn(missing_docs)]
pub use self::Mode::{Encrypt, Decrypt};
pub use self::DeltaLError::{Io, InvalidHeader, ChecksumMismatch};

use std::hash::{Hash, Hasher, SipHasher};
use std::num::Wrapping;

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
    ChecksumMismatch,
}

impl fmt::Display for DeltaLError{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result{
        match *self{
            Io(ref err)      => err.fmt(f),
            InvalidHeader    => write!(f, "The header was not valid."),
            ChecksumMismatch => write!(f, "The checksum of the output file did not match the checksum in the header."),
        }
    }
}

impl Error for DeltaLError{
    fn description(&self) -> &str{
        match *self{
            Io(ref err)      => err.description(),
            InvalidHeader    => "header wasn't valid",
            ChecksumMismatch => "checksum of output file didn't match header checksum",
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
        self.passhash = hash_as_array(passphrase)
    }

    fn offset(&self, b: u8, i: usize) -> u8{
        if self.is_mode_encrypt(){
            Wrapping(b) + Wrapping(self.passhash[i % 8])
        }else{
            Wrapping(b) - Wrapping(self.passhash[i % 8])
        }.0
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
    pub fn execute<FP: AsRef<Path>, TP: AsRef<Path>>(&self, from_path: FP, to_path: TP) -> Result<String>{
        let coded_buffer = {
            let mut f = try!(File::open(&from_path));
            let mut buffer = Vec::<u8>::new();

            try!(f.read_to_end(&mut buffer));

            let mut coded_buffer = Vec::<u8>::new();

            let mut skip = 0;
            let mut checksum: Option<[u8; 8]> = None;

            // Do header related things
            if let Encrypt{checksum} = self.mode {
                // Makes delta symbol: Δ
                coded_buffer.push(206);
                coded_buffer.push(148);

                // Capital L (76) if checksum is enabled, lowercase (108) if disabled
                if checksum {
                    coded_buffer.push(76);
                    coded_buffer.push(10); // Push a newline

                    for b in &hash_as_array(&buffer){
                        coded_buffer.push(*b)
                    }
                } else {
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
                }else{
                    return Err(InvalidHeader)
                }
            }

            {
                let mut buffer_iter = buffer.iter().map(|b| *b).skip(skip).enumerate();

                // Handle the first byte specially outside for loop
                if let Some((i, b)) = buffer_iter.next(){
                    coded_buffer.push(self.offset(b, i))
                }

                // Loop over every byte in the file buffer, along with the index of that byte
                for (i, b) in buffer_iter{
                    // Adds/substracts the byte (plus/minus the offset) with the previous byte, using Wrapping to ignore over- and underflow
                    let Wrapping(result) = match self.mode {
                        Encrypt{..} => Wrapping(self.offset(b, i)) + Wrapping(buffer[i-1]),
                        Decrypt     => Wrapping(self.offset(b, i)) - Wrapping(coded_buffer[i-1]),
                    };

                    coded_buffer.push(result)
                }
            }

            if let Some(check) = checksum {
                if check != hash_as_array(&coded_buffer){
                    return Err(ChecksumMismatch)
                }
            }

            coded_buffer
        };

        let mut result_file = try!(File::create(&to_path));

        try!(result_file.write_all(&coded_buffer));

        Ok(to_path.as_ref().to_str().unwrap().to_string())
    }
}

#[inline]
fn slice_to_array(slice: &[u8]) -> [u8; 8]{
    [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]
}

fn hash_as_array<T: Hash>(h: T) -> [u8; 8]{
    let mut siphasher = SipHasher::new();
    h.hash(&mut siphasher);

    unsafe {::std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())}
}
