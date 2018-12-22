#![warn(clippy::all)]

use delta_l::Error::{Io, InvalidHeader, ChecksumMismatch};

use delta_l as dl;

use std::env;
use std::string::String;

use std::io::ErrorKind::NotFound;

use getopts::Options;

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
    let args = &env::args().collect::<Vec<String>>()[1..];

    let mut opts = Options::new();
    opts.optflag("?", "help", "Prints this help menu.");
    opts.optopt("p", "", "Encrypts/decrypts with a passphrase.", "<passphrase>");
    opts.optopt("o", "", "Sets the output file.", "<output-file>");
    opts.optflag("y", "yes", "Overwrites output file without prompt, if it already exists.");
    opts.optflag("c", "checksum", "Disables checksum feature when encrypting: - This is read from the header when decrypting.");

    let matches = match opts.parse(args){
        Ok(m) => m,
        Err(_) => return incorrect_syntax(),
    };

    if matches.opt_present("?"){
        return print!("{}", opts.usage(USAGE));
    }

    if matches.free.len() != 2{
        return incorrect_syntax();
    }

    let file_path = &*matches.free[1];

    let mode = match &*matches.free[0]{
        "e"|"encrypt" => Encrypt,
        "d"|"decrypt" => Decrypt,
        _ => return incorrect_syntax()
    };

    let to_file = matches.opt_str("o");
    let passphrase = matches.opt_str("p");
    let checksum = !matches.opt_present("c");
    let force_overwite = matches.opt_present("y");

    let passhash = if let Some(ref pp) = passphrase{
        dl::get_passhash(pp)
    }else{[0; 8]};

    let to: PathBuf = to_file
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
        (Encrypt, true) => dl::encode_with_checksum(passhash, &mut f, &mut result_file).map_err(From::from),
        (Encrypt, false) => dl::encode_no_checksum(passhash, &mut f, &mut result_file).map_err(From::from),
        (Decrypt, true) => dl::decode(passhash, &mut f, &mut result_file),
        (Decrypt, false) => {
            println!("Checksum flag is only available when encrypting.\n");
            return incorrect_syntax()
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

use std::path::PathBuf;
use std::fs::File;

const USAGE: &str = r#"Delta L encryption program

Usage:
    delta-l <MODE> <FILE> [OPTIONS]
    delta-l -?

Modes:
    e[ncrypt]           Encrypts a file
    d[ecrypt]           Decrypts a file"#;

#[inline]
fn incorrect_syntax(){
    println!("Incorrect syntax:\n    Type delta-l -? for help")
}
