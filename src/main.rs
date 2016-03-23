extern crate delta_l as dl;

use dl::DeltaL;
use dl::Mode::{Encrypt, Decrypt};
use dl::DeltaLError::{Io, InvalidHeader, ChecksumMismatch};

use std::env;
use std::string::String;

use std::io::ErrorKind::NotFound;

fn main() {
    if env::args().len() < 2 { // The raw args contain the programme itself too, which is ommited in the args variable defined below.
        return incorrect_syntax()
    }

    let args = &env::args().collect::<Vec<String>>()[1..];

    if args.len() < 2 {
        match &*args[0] {
            "-?"|"-h"|"--help" => return println!("{}", USAGE),
            _                  => return incorrect_syntax(),
        }
    }

    let file_path = &*args[1];

    let mut dl = DeltaL::new(match &*args[0]{
        "e"|"encrypt" => Encrypt{checksum: true},
        "d"|"decrypt" => Decrypt,
        _ => return incorrect_syntax()
    });

    let mut to_file   : Option<usize> = None;
    let mut passphrase: Option<usize> = None;
    let mut checksum                 = false;
    let mut force_overwite           = false;
    let mut force                    = false;

    for (index, arg) in args.iter().enumerate().skip(2){
        if index == to_file.unwrap_or_default() || index == passphrase.unwrap_or_default(){
            continue
        }

        if arg[0..1].eq("-"){
            match &arg[1..] {
                "p"|"-passphrase" =>
                    if let None = passphrase {
                        passphrase = Some(index+1)
                    } else {
                        return incorrect_syntax()
                    },
                "t"|"-to" =>
                    if let None = to_file {
                        to_file = Some(index+1)
                    } else {
                        return incorrect_syntax()
                    },
                "y"|"-yes" =>
                    if !force_overwite {
                        force_overwite = true
                    } else {
                        return incorrect_syntax()
                    },
                "f"|"-force" =>
                    if !force {
                        force = true
                    } else {
                        return incorrect_syntax()
                    },
                "c"|"-checksum" =>
                    if !checksum {
                        checksum = dl.set_checksum(false);

                        if !checksum{
                            println!("Checksum flag is only available when encrypting.\n");
                            return incorrect_syntax()
                        }
                    } else {
                        return incorrect_syntax()
                    },

                _ => return incorrect_syntax()
            }
        }else{
            return incorrect_syntax()
        }
    }

    if let Some(i) = passphrase{
        dl.set_passphrase(&args[i])
    }

    let to: PathBuf = From::from(match to_file{
        Some(i) => args[i].to_owned(),
        None => file_path.to_string() + dl.get_mode_standard_extension(),
    });

    if to.exists() && !force_overwite{
        println!("Output file already exists; do you want to overwrite (yes/no)?");

        let stdin = std::io::stdin();

        loop{
            let mut answer = String::new();
            stdin.read_line(&mut answer).unwrap();

            match answer.trim().as_ref(){
                "yes" => break,
                "no"  => return println!("{}cryption has been cancelled.", if dl.is_mode_encrypt() {"En"} else {"De"}),
                _ => println!("Please answer yes or no:"),
            }
        }
    }

    match dl.execute(file_path) {
        Ok(res_vec) => {
            save(res_vec, &to).unwrap();
            println!("Result file has been saved to {}", to.to_str().unwrap_or("<nil>"))
        },
        Err(e) => match e {
            Io(e) => match e.kind(){
                NotFound     => println!("Couldn't find the specified file.\nPlease make sure the file exists."),
                _            => println!("An unknown error occured, encrypting the file:\n{:?}", e)
            },
            InvalidHeader    => println!("Invalid header error:\nThe specified file wasn't a valid .delta file."),
            ChecksumMismatch(res_vec) => if force{
                    println!("Checksum mismatch detetected! Saving anyways because of force flag");
                    save(res_vec, &to).unwrap();
                }else{
                    println!("Decryption failed:\nIncorrect passphrase.")
                }
        },
    }
}

use std::path::PathBuf;
use std::fs::File;
use std::io::{Write, Result as IOResult};

fn save(res_vec: Vec<u8>, to_path: &PathBuf) -> IOResult<()>{
    let mut result_file = try!(File::create(to_path));

    result_file.write_all(&res_vec)
}


const USAGE: &'static str = r#"Delta L encryption program

Usage:
    delta-l <mode> <file> [options]
    delta-l -?

Modes:
    encrypt             Encrypts a file
    decrypt             Decrypts a file

Options:
    -p <passphrase>     Encrypts/decrypts with a passphrase.
    -t <output-file>    Specifies the output file.
    -y                  Forces overwriting of an existing file without prompt.
    -c                  Disables checksum feature when encrypting. This is read from the header when decrypting.
    -f                  Forces the resulting file to be created even if the checsums mismatch during decryption."#;

fn incorrect_syntax(){
    println!("Incorrect syntax:\n    Type delta-l -? for help")
}
