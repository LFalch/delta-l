extern crate delta_l;

use delta_l::*;

use std::env;
use std::string::String;

use std::io::ErrorKind::NotFound;

fn main() {
    let args = &*&env::args().collect::<Vec<String>>()[1..];

    if args.len() < 1 {
        return incorrect_syntax();
    }

    let file_path = match &*args[0]{
        "-?"|"-h"|"--help" => return println!("{}", USAGE),
        some => some,
    }.to_string();

    let mut dlb = DeltaLBuilder::new();

    let mut mode      : Option<Mode > = None;
    let mut to_file   : Option<usize> = None;
    let mut passphrase: Option<usize> = None;

    for (index, arg) in args.iter().enumerate(){
        // if index == 0 {continue} // default of a usize is 0 so this line is essentially down there.

        if index == to_file.unwrap_or_default(){
            continue;
        }else if index == passphrase.unwrap_or_default(){
            continue;
        }

        if arg[0..1].eq("-"){
            match &arg[ 1..arg.len() ] {
                "e"|"-encrypt" =>
                    if let None = mode {
                        mode = Some(Encrypt)
                    } else {
                        return incorrect_syntax()
                    },
                "d"|"-decrypt" =>
                    if let None = mode {
                        mode = Some(Decrypt)
                    } else {
                        return incorrect_syntax()
                    },
                "p" =>
                    if let None = passphrase {
                        passphrase = Some(index+1)
                    } else {
                        return incorrect_syntax()
                    },
                "t" =>
                    if let None = to_file {
                        to_file = Some(index+1)
                    } else {
                        return incorrect_syntax()
                    },
                _ => return incorrect_syntax()
            }
        }
    }


    dlb = match mode {
        Some(m) => dlb.mode(m),
        None    => return incorrect_syntax(),
    };

    if let Some(i) = passphrase{
        dlb = dlb.coding(Coding::new_offset(&args[i]))
    }

    let dl = dlb.build().unwrap(); // Unwrap should be safe since it would've had an incorrect syntax error, if mode wasn't specified

    let res = match to_file{
        Some(i) => code_to(file_path, &args[i], dl),
        None    => code   (file_path,           dl)
    };

    match res{
        Ok (path) => println!("Result file has been saved to {}", path),
        Err( e  ) => match e.kind(){
            NotFound => println!("Couldn't find the specified file.\nPlease make sure the file exists."),
            _        => println!("An unknown error occured, encrypting the file:\n{:?}", e)
        },
    }
}

const USAGE: &'static str = r#"Delta L encryption program

Usage:
    delta-l <file> <mode> [options]
    delta-l -?

Modes:
    -e, --encrypt
    -d, --decrypt

Options:
    -p <passphrase>  Encrypts with a passphrase.
    -t <output-file> Specifies the output file."#;

fn incorrect_syntax(){
    println!("Incorrect syntax:\n\nType delta-l -? for help")
}

/*fn get_v_args() -> Box<[String]>{
    let mut v_args = Vec::new();

    for argument in env::args().skip(1) {
        v_args.push(argument);
    }
    v_args.into_boxed_slice()
}*/
