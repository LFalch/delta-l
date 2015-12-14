extern crate delta_l;

use delta_l::*;

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

    let mut dlb = DeltaLBuilder::new()
        .mode(match &*args[0]{
            "e"|"encrypt" => Encrypt,
            "d"|"decrypt" => Decrypt,
            _ => return incorrect_syntax()
        });

    let mut to_file   : Option<usize> = None;
    let mut passphrase: Option<usize> = None;
    let mut force_overwite           = false;

    for (index, arg) in args.iter().skip(2).enumerate().map(|(i, x)| (i+2, x)){
        // if index == 0 {continue} // default of a usize is 0 so this line is essentially down there. Also

        if index == to_file.unwrap_or_default() || index == passphrase.unwrap_or_default(){
            continue
        }

        if arg[0..1].eq("-"){
            match &arg[1..] {
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
                "y" =>
                    if !force_overwite {
                        force_overwite = true
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
        dlb = dlb.coding(Coding::new_offset(&args[i]))
    }

    let dl = dlb.build().unwrap(); // Unwrap should be safe since it would've had an incorrect syntax error, if mode wasn't specified

    let res = match to_file {
        Some(i) => code(file_path, &args[i], force_overwite, dl),
        None    => {
            let to = format!("{}{}", file_path, dl.get_mode_standard_extension());
            code(file_path, &to, force_overwite, dl)
        }
    };

    match res {
        Ok(Some(path)) => println!("Result file has been saved to {}", path),
        Err    ( e  )  => match e.kind() {
            NotFound => println!("Couldn't find the specified file.\nPlease make sure the file exists."),
            _        => println!("An unknown error occured, encrypting the file:\n{:?}", e)
        },
        Ok(None) => println!("{}cryption has been cancelled.", if dl.mode().is_encrypt() {"En"} else {"De"}),
    }
}

use std::path::Path;

fn code(p: &str, to: &str, force_overwite: bool, dl: DeltaL) -> std::io::Result<Option<String>>{
    let to = Path::new(to);

    if to.exists() && !force_overwite{
        println!("Output file already exists; do you want to overwrite (yes/no)?");

        let stdin = std::io::stdin();
        let mut answer = String::new();

        loop{
            try!(stdin.read_line(&mut answer));
            match answer.trim().as_ref(){
                "yes" => break,
                "no"  => return Ok(None),
                _ => println!("Please answer yes or no:"),
            }
        }
    }
    // If the Result is Ok(x), map it with Some so as to return Ok(Some(x))
    code_to(p, to, dl).map(Some)
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
    -y                  Forces overwriting of an existing file without prompt."#;

fn incorrect_syntax(){
    println!("Incorrect syntax:\n\nType delta-l -? for help")
}
