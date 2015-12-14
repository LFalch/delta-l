//! Crate for using Delta-L encryption
#![warn(missing_docs)]
pub use Coding::{Pure, Offset};
pub use Mode::{Encrypt, Decrypt};

use std::hash::{Hash, Hasher, SipHasher};
use std::num::Wrapping;

use std::fs::File;
use std::path::Path;
use std::io::{Result, Read, Write};

/// Provides interface for Delta-L encryption/decryption
#[derive(Debug, Copy, Clone)]
pub struct DeltaL{
    mode  : Mode,
    coding: Coding
}

impl DeltaL{
    /// Creates a DeltaL instance
    pub fn new(mode: Mode, coding: Coding) -> DeltaL{
        DeltaL{
            mode  : mode,
            coding: coding
        }
    }

    /// Calculates the offset on the index and adds that the byte to then return it
    pub fn offset(&self, b: u8, i: usize) -> u8{
        if self.mode.is_encrypt(){
            Wrapping(b) + Wrapping(self.coding.get_offset(i))
        }else{
            Wrapping(b) - Wrapping(self.coding.get_offset(i))
        }.0
    }

    /// Gets the standard extension of the `Mode` (See `Mode` documentation)
    pub fn get_mode_standard_extension(&self) -> &'static str{
        self.mode.get_standard_extension()
    }

    /// Returns the mode field
    pub fn mode(&self) -> &Mode{
        &self.mode
    }

    /// Codes the file in from_path to the file in to_path
    pub fn execute<FP: AsRef<Path>, TP: AsRef<Path>>(&self, from_path: FP, to_path: TP) -> Result<String>{
        let coded_buffer = {
            // Open the file
            let mut f = try!(File::open(&from_path));

            // Create buffer for holding the bytes of the file
            let mut buffer = Vec::<u8>::new();

            // Reading the file into the buffer
            // (The amount of bytes read gets returned by read_to_end).
            try!(f.read_to_end(&mut buffer));


            // TODO HEADER


            // Create buffer for holding the coded bytes
            let mut coded_buffer = Vec::<u8>::new();

            let mut buffer_iter = buffer.iter().enumerate();

            // Handle the first byte specially outside for loop
            match buffer_iter.next(){
                Some((i, b)) => coded_buffer.push(self.offset(*b, i)),
                None => ()
            }

            // Loop over every byte in the file buffer, along with the index of that byte
            for (i, b) in buffer_iter{
                // Adds/substracts (adds during encryption, and the opposite during the opposite) the byte with the previous, using Wrapping to ignore over- and underflow (plus/minus the offset)
                let Wrapping(result) = match self.mode {
                    Encrypt => Wrapping(self.offset(*b, i)) + Wrapping(buffer[i-1]),
                    Decrypt => Wrapping(self.offset(*b, i)) - Wrapping(coded_buffer[i-1]),
                };

                coded_buffer.push(result)
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

const DELTA: char = 'Δ';

/// A struct for conveniently making a `DeltaL` instance
pub struct DeltaLBuilder{
    mode  : Option<Mode>,
    coding: Option<Coding>
}

impl DeltaLBuilder{
    /// Instantiates a `DeltaLBuilder` object
    pub fn new() -> DeltaLBuilder{
        DeltaLBuilder{
            mode: None,
            coding: None,
        }
    }

    /// Specifies the `Mode` of the to-be-built `DeltaL`
    pub fn mode(self, m: Mode) -> DeltaLBuilder{
        DeltaLBuilder{
            mode: Some(m),
            ..
            self
        }
    }

    /// Specifies the `Coding` of the to-be-built `DeltaL`
    pub fn coding(self, c: Coding) -> DeltaLBuilder{
        DeltaLBuilder{
            coding: Some(c),
            ..
            self
        }
    }

    /// Creates a `DeltaL` if all fields have been specified, otherwise `None`
    pub fn build(self) -> Option<DeltaL>{
        if let Some(mode) = self.mode{
            Some(DeltaL{
                mode  : mode,
                coding: self.coding.unwrap_or_default(),
            })
        }else{
            None
        }
    }
}

/// Specifies whether to use a passphrase or not
#[derive(Debug, Copy, Clone)]
pub enum Coding {
    /// A coding without passphrase
    Pure,
    /// A coding that uses a hash generated from a passphrase
    Offset{
        /// The hash of the passphrase as a byte array, to be used as offsets
        passhash: [u8; 8]
    },
}

/// Specifies whether to en- or decrypt
#[derive(Debug, Copy, Clone)]
pub enum Mode{
    /// Specifies that we're encrypting
    Encrypt,
    /// Specifies that we're encrypting
    Decrypt,
}

impl Mode {
    /// Returns ".delta" for encryption and ".dec" for decryption
    pub fn get_standard_extension(&self) -> &'static str{
        match *self{
            Encrypt => ".delta",
            Decrypt => ".dec",
        }
    }
    /// Returns whether the Mode is Encrypt
    pub fn is_encrypt(&self) -> bool{
        match *self{
            Encrypt => true,
            _       => false, // To emphasise that every other value wouldn't be Encrypt
        }
    }
    /// Returns whether the Mode is Decrypt
    pub fn is_decrypt(&self) -> bool{
        match *self{
            Decrypt => true,
            _       => false, // To emphasise that every other value wouldn't be Decrypt
        }
    }
}

impl Coding {
    /// New `Offset` variant of `Coding`
    pub fn new_offset(passphrase: &str) -> Coding{
        let mut siphasher = SipHasher::new();
        passphrase.hash(&mut siphasher);

        Offset{
            passhash: unsafe{
                std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())
            }
        }
    }

    /// Returns the offset for a given index
    pub fn get_offset(&self, i: usize) -> u8{
        match *self{
            Pure => 0,
            Offset{passhash: ref hash} => hash[i % 8]
        }
    }

    /// Returns whether this is the variant `Pure`
    pub fn is_pure(&self) -> bool{
        match *self{
            Pure => true,
            _    => false, // To emphasise that every other value wouldn't be Pure
        }
    }
}

impl Default for Coding{
    fn default() -> Coding{
        Pure
    }
}
