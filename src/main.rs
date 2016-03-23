extern crate delta_l as dl;
extern crate getopts;

use dl::DeltaL;
use dl::Mode::{Encrypt, Decrypt};
use dl::DeltaLError::{Io, InvalidHeader, ChecksumMismatch};

use std::env;
use std::string::String;

use std::io::ErrorKind::NotFound;

use getopts::Options;

fn main() {
    let args = &env::args().collect::<Vec<String>>()[1..];

    let mut opts = Options::new();
    opts.optflag("?", "help", "Prints this help menu.");
    opts.optopt("p", "", "Encrypts/decrypts with a passphrase.", "<passphrase>");
    opts.optopt("o", "", "Sets the output file.", "<output-file>");
    opts.optflag("y", "yes", "Overwrites output file without prompt, if it already exists.");
    opts.optflag("c", "checksum", "Disables checksum feature when encrypting: - This is read from the header when decrypting.");
    opts.optflag("f", "force", "Forces the resulting file to be created even if the checksums mismatch during decryption.");

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

    let mut dl = DeltaL::new(match &*matches.free[0]{
        "e"|"encrypt" => Encrypt{checksum: true},
        "d"|"decrypt" => Decrypt,
        _ => return incorrect_syntax()
    });

    let to_file = matches.opt_str("o");
    let passphrase = matches.opt_str("p");
    let checksum = matches.opt_present("c");
    let force = matches.opt_present("f");
    let force_overwite = matches.opt_present("y");

    if checksum {
        if dl.is_mode_encrypt(){
            dl.set_checksum(false);
        }else{
            println!("Checksum flag is only available when encrypting.\n");
            return incorrect_syntax()
        }
    }

    if let Some(pp) = passphrase{
        dl.set_passphrase(&pp);
    }

    let to: PathBuf = to_file
        .unwrap_or(file_path.to_owned() + dl.get_mode_standard_extension())
        // From `String` into `PathBuf`
        .into();

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
    delta-l <MODE> <FILE> [OPTIONS]
    delta-l -?

Modes:
    e[ncrypt]           Encrypts a file
    d[ecrypt]           Decrypts a file"#;

fn incorrect_syntax(){
    println!("Incorrect syntax:\n    Type delta-l -? for help")
}
