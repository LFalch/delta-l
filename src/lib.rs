//! Crate for using Delta-L encryption
pub use Coding::{Pure, Offset};
pub use Mode::{Encrypt, Decrypt};

use std::hash::{Hash, Hasher, SipHasher};
use std::num::Wrapping;

use std::fs::File;
use std::path::Path;
use std::io::{Result, Read, Write};

// Bundle the Mode and Variation together
#[derive(Debug, Copy, Clone)]
pub struct DeltaL{
    pub mode  : Mode,
    pub coding: Coding
}

impl DeltaL{
    pub fn new(mode: Mode, coding: Coding) -> DeltaL{
        DeltaL{
            mode  : mode,
            coding: coding
        }
    }

    pub fn offset(&self, b: u8, i: &usize) -> u8{
        if self.mode.is_encrypt(){
            Wrapping(b) + Wrapping(self.coding.get_offset(i))
        }else{
            Wrapping(b) - Wrapping(self.coding.get_offset(i))
        }.0
    }
}

pub struct DeltaLBuilder{
    mode  : Option<Mode>,
    coding: Option<Coding>
}

impl DeltaLBuilder{
    pub fn new() -> DeltaLBuilder{
        DeltaLBuilder{
            mode: None,
            coding: None,
        }
    }

    pub fn mode(self, m: Mode) -> DeltaLBuilder{
        DeltaLBuilder{
            mode: Some(m),
            ..
            self
        }
    }

    pub fn coding(self, c: Coding) -> DeltaLBuilder{
        DeltaLBuilder{
            coding: Some(c),
            ..
            self
        }
    }

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

/// Specify whether to use a passphrase or not
#[derive(Debug, Copy, Clone)]
pub enum Coding {
    Pure,
    Offset{
        passhash: [u8; 8]
    },
}

/// Specify whether to en- or decrypt
#[derive(Debug, Copy, Clone)]
pub enum Mode{
    Encrypt,
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
    pub fn new_offset(passphrase: &str) -> Coding{
        let mut siphasher = SipHasher::new();
        passphrase.hash(&mut siphasher);

        Offset{
            passhash: unsafe{
                std::mem::transmute::<u64, [u8; 8]>(siphasher.finish())
            }
        }
    }

    pub fn get_offset(&self, i: &usize) -> u8{
        match *self{
            Pure => 0,
            Offset{passhash: ref hash} => hash[*i % 8]
        }
    }

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

/// Codes the file to a file using the same path with an appended ".delta" or ".dec"
/// Returns the path to the encoded file as a String
pub fn code<P: AsRef<Path>>(p: P, dl: DeltaL) -> Result<String>{
    let to = format!("{}{}", p.as_ref().to_str().unwrap(), dl.mode.get_standard_extension());
    try!(code_to(p, &to, dl));

    Ok(to)
}

/// Codes the file in from_path to the file in to_path
pub fn code_to<FP: AsRef<Path>, TP: AsRef<Path>>(from_path: FP, to_path: TP, dl: DeltaL) -> Result<String>{
    let coded_buffer = {
        // Open the file
        let mut f = try!(File::open(&from_path));

        // Create buffer for holding the bytes of the file
        let mut buffer = Vec::<u8>::new();

        // Reading the file into the buffer, and storing the length
        // (The amount of bytes read gets returned by read_to_end).
        let _len = try!(f.read_to_end(&mut buffer));

        // Create buffer for holding the coded bytes
        let mut coded_buffer = Vec::<u8>::new();

        // Loop over every byte in the file buffer, along with the index of that byte
        for (i, b) in buffer.iter().enumerate(){
            if i == 0{
                // The first byte of the coded file will be the same, since there was no previous byte (plus/minus the offset)
                coded_buffer.push(dl.offset(*b, &i))
            }else{
                // Adds/substracts (Adds during encryption, and the opposite during the opposite) the byte with the previous, using Wrapping to ignore over- and underflow (plus/minus the offset)
                let Wrapping(result) = match dl.mode {
                    Encrypt => Wrapping(dl.offset(*b, &i)) + Wrapping(buffer[i-1]),
                    Decrypt => Wrapping(dl.offset(*b, &i)) - Wrapping(coded_buffer[i-1]),
                };

                coded_buffer.push(result)
            }
        }

        coded_buffer
    };

    // Creates a file using the input to_path
    let mut result_file = try!(File::create(&to_path));

    // Writes the coded buffer into the file
    try!(result_file.write_all(&*coded_buffer.into_boxed_slice()));

    // Returns that all went well, if nothing went wrong
    Ok(to_path.as_ref().to_str().unwrap().to_string())
}
