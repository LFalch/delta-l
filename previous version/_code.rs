//! This is the original implementation of Delta L encryption

use std::fs::File;
use std::path::Path;
use std::io::{Result, Read, Write};

use std::num::Wrapping;

/// Encodes the file to a file using the same path with an appended ".delta"
/// Returns the path to the encoded file as a String
pub fn encode<P: AsRef<Path>>(p: P) -> Result<String>{
    let to = format!("{}{}", p.as_ref().to_str().unwrap(), ".delta");
    try!(encode_to(p, &to));

    Ok(to)
}

/// Encodes the file in from_path to to file in to_path
pub fn encode_to<FP: AsRef<Path>, TP: AsRef<Path>>(from_path: FP, to_path: TP) -> Result<()>{
    let encoded_buffer = {
        // Open the file
        let mut f = try!(File::open(&from_path));

        // Create buffer for holding the bytes of the file
        let mut buffer = Vec::<u8>::new();

        // Reading the file into the buffer, and storing the length
        // (The amount of bytes read gets returned by read_to_end).
        let len = try!(f.read_to_end(&mut buffer));

        // Create buffer for holding the encoded bytes
        let mut encoded_buffer = Vec::<u8>::new();

        // Loop over every byte in the file buffer, along with the index of that byte
        for (b, i) in buffer.iter().zip(0..len){ // zipping a range containg all indices together with the buffer, returing an iterator over [(&u8, usize)]
            if i == 0{
                // The first byte of the encoded file will be the same, since there was no previous byte
                encoded_buffer.push(*b)
            }else{
                // Subtracts the byte with the previous, using Wrapping to ignore over- and underflow
                let Wrapping(result) = Wrapping(*b) - Wrapping(buffer[i-1]);
                encoded_buffer.push(result);
            }
        }

        encoded_buffer
    };

    // Creates a file using the input to_path
    let mut return_file = try!(File::create(to_path)); // The unwrap should be fine, since the file above would've had errored loading if the path was wrong.

    // Writes the encoded buffer into the file
    try!(return_file.write_all(&*encoded_buffer.into_boxed_slice()));

    // Returns that all went well, if nothing went wrong
    Ok(())
}

/// Decodes the file to a file using the same path with an appended ".dec"
/// Returns the path to the decoded file as a String
pub fn decode<P: AsRef<Path>>(p: P) -> Result<String>{
    let to = format!("{}{}", p.as_ref().to_str().unwrap(), ".dec");
    try!(decode_to(p, &to));

    Ok(to)
}

/// Decodes the file in from_path to to file in to_path
pub fn decode_to<FP: AsRef<Path>, TP: AsRef<Path>>(from_path: FP, to_path: TP) -> Result<()>{
    let decoded_buffer = {
        // Open the file
        let mut f = try!(File::open(&from_path));

        // Create buffer for holding the bytes of the file
        let mut buffer = Vec::<u8>::new();

        // Reading the file into the buffer, and storing the length
        // (The amount of bytes read gets returned by read_to_end).
        let len = try!(f.read_to_end(&mut buffer));

        // Create buffer for holding the decoded bytes
        let mut decoded_buffer = Vec::<u8>::new();

        // Loop over every byte in the file buffer, along with the index of that byte
        for (b, i) in buffer.iter().zip(0..len){ // zipping a range containg all indices together with the buffer, returing an iterator over [(&u8, usize)]
            if i == 0{
                // The first byte of the decoded file will be the same, since there was no previous byte
                decoded_buffer.push(*b)
            }else{
                // Adds the byte with the previously decode byte, using Wrapping to ignore over- and underflow
                let Wrapping(result) = Wrapping(*b) + Wrapping(decoded_buffer[i-1]);
                decoded_buffer.push(result);
            }
        }

        decoded_buffer
    };

    // Creates a file using the input to_path
    let mut return_file = try!(File::create(to_path)); // The unwrap should be fine, since the file above would've had errored loading if the path was wrong.

    // Writes the decoded buffer into the file
    try!(return_file.write_all(&*decoded_buffer.into_boxed_slice()));

    // Returns that all went well, if nothing went wrong
    Ok(())
}
