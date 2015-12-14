//! Crate for using Delta-L encryption
#![warn(missing_docs)]
pub use Mode::{Encrypt, Decrypt};
pub use DeltaLError::{Io, InvalidHeader, ChecksumMismatch};

use std::hash::{Hash, Hasher, SipHasher};
use std::num::Wrapping;

use std::fs::File;
use std::path::Path;
use std::io::{Read, Write};
use std::io;

/// Convinent `Result` type for `DeltaLError`
pub type DLResult<T> = std::result::Result<T, DeltaLError>;

/// Decribes errors that can occur doing encryption or decryption
pub enum DeltaLError{
    /// Errors that are just plain IO errors
    Io(io::Error),
    /// Invalid header error
    InvalidHeader,
    /// Checksum mismatch error
    ChecksumMismatch,
}

impl From<io::Error> for DeltaLError{
    fn from(e: io::Error) -> DeltaLError{
        DeltaLError::Io(e)
    }
}

/// Provides interface for Delta-L encryption/decryption
#[derive(Debug, Copy, Clone)]
pub struct DeltaL{
    mode     : Mode,
    offsetter: Offsetter,
}

impl DeltaL{
    /// Creates a `DeltaL` instance
    pub fn new(mode: Mode) -> DeltaL{
        DeltaL{
            mode     : mode,
            offsetter: Offsetter::new_pure(),
        }
    }

    /// Enables/disables checksum, if mode is `Encrypt`
    pub fn set_checksum(&mut self, chcksum: bool) -> Result<(), ()>{
        match self.mode{
            Encrypt{ref mut checksum} => {
                *checksum = chcksum;
                Ok(())
            }
            Decrypt => Err(())
        }
    }

    /// Sets the passphrase for the `DeltaL`
    pub fn set_passphrase(&mut self, passphrase: &str){
        self.offsetter = Offsetter::new(passphrase)
    }

    fn offset(&self, b: u8, i: usize) -> u8{
        if self.mode.is_encrypt(){
            Wrapping(b) + Wrapping(self.offsetter.get_offset(i))
        }else{
            Wrapping(b) - Wrapping(self.offsetter.get_offset(i))
        }.0
    }

    /// Returns ".delta" for encryption and ".dec" for decryption
    pub fn get_mode_standard_extension(&self) -> &'static str{
        self.mode.get_standard_extension()
    }

    /// Returns whether the mode is `Encrypt`
    pub fn is_mode_encrypt(&self) -> bool{
        self.mode.is_encrypt()
    }

    /// Returns whether the mode is `Decrypt`
    pub fn is_mode_decrypt(&self) -> bool{
        self.mode.is_decrypt()
    }

    /// Codes the file in from_path to the file in to_path
    pub fn execute<FP: AsRef<Path>, TP: AsRef<Path>>(&self, from_path: FP, to_path: TP) -> DLResult<String>{
        let coded_buffer = {
            // Open the file
            let mut f = try!(File::open(&from_path));

            // Create buffer for holding the bytes of the file
            let mut buffer = Vec::<u8>::new();

            // Reading the file into the buffer
            // (The amount of bytes read gets returned by read_to_end).
            try!(f.read_to_end(&mut buffer));

            // Create buffer for holding the coded bytes
            let mut coded_buffer = Vec::<u8>::new();

            let mut skip = 0;

            let mut checksum: Option<[u8; 8]> = None;

            // Do header related things
            if let Encrypt{checksum} = self.mode {
                // Makes delta symbol: Δ
                coded_buffer.push(206);
                coded_buffer.push(148);

                // Capital L (76) if checksum is enanbled, lowercase (108) if disabled
                if checksum {
                    coded_buffer.push(76);
                    coded_buffer.push(10); // Push a newline

                    for b in &hash_vec_u8(&buffer){
                        coded_buffer.push(*b)
                    }
                } else {
                    coded_buffer.push(108);
                    coded_buffer.push(10); // Push a newline
                }
            } else {
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

            let mut buffer_iter = buffer.iter().skip(skip).enumerate();

            // Handle the first byte specially outside for loop
            match buffer_iter.next(){
                Some((i, b)) => coded_buffer.push(self.offset(*b, i)),
                None => ()
            }

            // Loop over every byte in the file buffer, along with the index of that byte
            for (i, b) in buffer_iter{
                // Adds/substracts (adds during encryption, and the opposite during the opposite) the byte with the previous, using Wrapping to ignore over- and underflow (plus/minus the offset)
                let Wrapping(result) = match self.mode {
                    Encrypt{..} => Wrapping(self.offset(*b, i)) + Wrapping(buffer[i-1]),
                    Decrypt     => Wrapping(self.offset(*b, i)) - Wrapping(coded_buffer[i-1]),
                };

                coded_buffer.push(result)
            }

            if let Some(check) = checksum {
                if check != hash_vec_u8(&coded_buffer){
                    return Err(ChecksumMismatch)
                }
            }

            coded_buffer
        };

        // Creates a file using the input to_path
        let mut result_file = try!(File::create(&to_path));

        // Writes the coded buffer into the file
        try!(result_file.write_all(&coded_buffer));

        // Returns that all went well, if nothing went wrong
        Ok(to_path.as_ref().to_str().unwrap().to_string())
    }
}

#[inline]
fn slice_to_array(slice: &[u8]) -> [u8; 8]{
    if slice.len() == 8{
        [slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7]]
    }else{
        unreachable!()
    }
}

#[inline]
fn hash_vec_u8(vec: &Vec<u8>) -> [u8; 8]{
    let mut siphasher = SipHasher::new();
    vec.hash(&mut siphasher);

    unsafe {std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())}
}

/// Specifies whether to encrypt or decrypt
#[derive(Debug, Copy, Clone)]
pub enum Mode{
    /// Specifies that we're encrypting
    Encrypt{
        /// Specifies whether to enable checksum verification
        checksum: bool
    },
    /// Specifies that we're encrypting
    Decrypt,
}

impl Mode {
    fn get_standard_extension(&self) -> &'static str{
        match *self{
            Encrypt{..} => ".delta",
            Decrypt     => ".dec",
        }
    }
    fn is_encrypt(&self) -> bool{
        match *self{
            Encrypt{..} => true,
            _           => false, // To emphasise that every other value wouldn't be Encrypt
        }
    }
    fn is_decrypt(&self) -> bool{
        match *self{
            Decrypt => true,
            _       => false, // To emphasise that every other value wouldn't be Decrypt
        }
    }
}

#[derive(Debug, Copy, Clone)]
struct Offsetter{
    passhash: [u8; 8]
}

impl Offsetter {
    pub fn new(passphrase: &str) -> Offsetter{
        let mut siphasher = SipHasher::new();
        passphrase.hash(&mut siphasher);

        Offsetter{
            passhash: unsafe{
                std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())
            }
        }
    }

    pub fn new_pure() -> Offsetter{
        Offsetter{
            passhash: [0; 8]
        }
    }

    pub fn get_offset(&self, i: usize) -> u8{
        self.passhash[i % 8]
    }
}
