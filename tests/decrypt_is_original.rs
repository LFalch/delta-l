extern crate delta_l;

use delta_l::DeltaL;
use delta_l::Mode::*;

use std::fs::File;
use std::io::{Write, Read, Result as IOResult};

const ORI_PATH: &'static str = "test_data/bench.txt";
const RES_PATH: &'static str = "test_data/test.delta";

#[test]
fn decrypt_is_orignal(){
    let res_vec = DeltaL::new(Encrypt{checksum: true}).execute(File::open(ORI_PATH).unwrap()).unwrap();
    File::create(RES_PATH).unwrap().write_all(&res_vec).unwrap();

    let dec_vec = DeltaL::new(Decrypt).execute(File::open(RES_PATH).unwrap()).unwrap();

    let original_vec = read(ORI_PATH).unwrap();

    assert_eq!(original_vec, dec_vec);
}

fn read(from_path: &str) -> IOResult<Vec<u8>>{
    let mut f = try!(File::open(from_path));
    let mut buffer = Vec::<u8>::new();

    try!(f.read_to_end(&mut buffer));

    Ok(buffer)
}
