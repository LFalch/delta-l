#![warn(clippy::all)]

use delta_l::{PassHashOffsetter, encode_no_checksum, encode_with_checksum, decode};
use delta_l::header::Error::{Io, InvalidHeader, ChecksumMismatch};

use std::path::PathBuf;
use std::fs::File;
use std::io::ErrorKind::NotFound;

use clap::{App, Arg};

#[derive(Debug, Copy, Clone)]
enum Mode{
    Encrypt, Decrypt
}

impl Mode{
    fn get_mode_standard_extension(self) -> &'static str{
        match self{
            Encrypt => ".delta",
            Decrypt => ".dec"
        }
    }
}

use crate::Mode::*;

fn main() {
    let matches = App::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg(Arg::with_name("MODE").required(true).possible_values(&["e", "encrypt", "d", "decrypt"]).help("Whether to encrypt or decrypt"))
        .arg(Arg::with_name("FILE").required(true).help("File to encrypt or decrypt"))
        .arg(Arg::with_name("passphrase")
            .short("p")
            .long("pass")
            .takes_value(true)
            .help("Encrypts/decrypts with a passphrase"),
        )
        .arg(Arg::with_name("output-file")
            .short("o")
            .long("out")
            .takes_value(true)
            .help("Sets the output file"),
        )
        .arg(Arg::with_name("yes")
            .short("y")
            .long("yes")
            .help("Overwrites output file without prompt, if it already exists"),
        )
        .arg(Arg::with_name("checksum")
            .short("c")
            .long("checksum")
            .help("Disables checksum feature when encrypting: - This is read from the header when decrypting"),
        )
        .get_matches();

    let file_path = matches.value_of("FILE").unwrap();

    let mode = match matches.value_of("MODE").unwrap() {
        "e"|"encrypt" => Encrypt,
        "d"|"decrypt" => Decrypt,
        _ => unreachable!()
    };

    let to_file = matches.value_of("output-file");
    let passphrase = matches.value_of("passphrase");
    let checksum = !matches.is_present("checksum");
    let force_overwite = matches.is_present("yes");

    let passhash = if let Some(ref pp) = passphrase{
        PassHashOffsetter::new(pp)
    }else{Default::default()};

    let to: PathBuf = to_file.map(|s| s.to_owned())
        .unwrap_or(file_path.to_owned() + mode.get_mode_standard_extension())
        // From `String` into `PathBuf`
        .into();

    if to.exists() && !force_overwite{
        println!("Output file already exists; do you want to overwrite (yes/no)?");

        let stdin = std::io::stdin();

        loop{
            let mut answer = String::new();
            stdin.read_line(&mut answer).unwrap();

            match answer.trim() {
                "yes" => break,
                "no"  => return println!("{}cryption has been cancelled.", if let Encrypt = mode {"En"} else {"De"}),
                _ => println!("Please answer yes or no:"),
            }
        }
    }

    let mut f = match File::open(file_path){
        Ok(f) => f,
        Err(e) => match e.kind(){
            NotFound => return println!("Couldn't find the specified file.\nPlease make sure the file exists."),
            _        => return println!("An unknown error occured, opening the file:\n{:?}", e)
        }
    };

    let mut result_file = File::create(&to).unwrap();

    let res = match (mode, checksum){
        (Encrypt, true) => encode_with_checksum(passhash, &mut f, &mut result_file).map_err(From::from),
        (Encrypt, false) => encode_no_checksum(passhash, &mut f, &mut result_file).map_err(From::from),
        (Decrypt, true) => decode(passhash, &mut f, &mut result_file),
        (Decrypt, false) => {
            eprintln!("Checksum flag is only available when encrypting.\n");
            return
        }
    };

    match res {
        Ok(()) => {
            println!("Result file has been saved to {}", to.to_str().unwrap_or("<nil>"))
        },
        Err(e) => match e {
            Io(e)         => println!("An unknown error occured, encrypting the file:\n{:?}", e.kind()),
            InvalidHeader => println!("Invalid header error:\nThe specified file wasn't a valid .delta file."),
            ChecksumMismatch => println!("Checksum mismatch detetected!\nPassphrase is probably incorrect."),
        },
    }
}
