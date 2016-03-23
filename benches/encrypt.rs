#![feature(test)]

extern crate test;
extern crate tempdir;
extern crate delta_l;

use delta_l::{DeltaL, Mode};
use tempdir::TempDir;

use std::fs::File;
use std::io::Write;

#[bench]
fn encrypt(b: &mut test::Bencher){
    let path = Path::new("test_data/bench.txt");
    assert!(path.exists(), "Please create the file: test_data/bench.txt");
    let dl = DeltaL::new(Mode::Encrypt{checksum: true});

    b.iter(|| dl.execute(path).unwrap());
}

fn save(res_vec: Vec<u8>, to_path: &str) -> std::io::Result<()>{
    let mut result_file = try!(File::create(to_path));

    result_file.write_all(&res_vec)
}

use std::path::Path;

#[bench]
fn decrypt(b: &mut test::Bencher){
    let path = Path::new("test_data/bench.txt");
    assert!(path.exists(), "Please create the file: test_data/bench.txt");
    save(DeltaL::new(Mode::Encrypt{checksum: true}).execute(path).unwrap(), "test_data/bench.txt.delta").unwrap();

    let dl = DeltaL::new(Mode::Decrypt);
    let path = Path::new("test_data/bench.txt.delta");

    b.iter(|| dl.execute(path).unwrap());
}
