extern crate tempdir;
extern crate delta_l;

use delta_l::{DeltaL, Mode};
use tempdir::TempDir;

use std::fs::File;
use std::path::Path;
use std::io::{Write, Read, Result as IOResult};

#[test]
fn decrypt_is_orignal(){
    let dir = TempDir::new("delta-l_test-").unwrap();

    let original_path = &dir.path().join("test.txt");
    let mut original = File::create(original_path).unwrap();
    write!(original, "Hello World!\nI'm a test!").unwrap();

    drop(original);

    let res_path = &dir.path().join("test.txt.delta");
    let res_vec = DeltaL::new(Mode::Encrypt{checksum: true}).execute(File::open(original_path).unwrap()).unwrap();
    save(res_vec, res_path).unwrap();

    let dec_vec = DeltaL::new(Mode::Decrypt).execute(File::open(res_path).unwrap()).unwrap();

    let original_vec = read(original_path).unwrap();

    assert_eq!(original_vec, dec_vec);
}

fn save(res_vec: Vec<u8>, to_path: &Path) -> IOResult<()>{
    let mut result_file = try!(File::create(to_path));

    result_file.write_all(&res_vec)
}

fn read(from_path: &Path) -> IOResult<Vec<u8>>{
    let mut f = try!(File::open(from_path));
    let mut buffer = Vec::<u8>::new();

    try!(f.read_to_end(&mut buffer));

    Ok(buffer)
}
