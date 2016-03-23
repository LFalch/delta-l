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
    let dir = TempDir::new("delta-l_bench-").unwrap();

    let path = &dir.path().join("test.txt");
    let mut file = File::create(path).unwrap();
    write!(file, "Hello, I'm used for the benchmark test!").unwrap();
    let dl = DeltaL::new(Mode::Encrypt{checksum: true});

    b.iter(|| dl.execute(path).unwrap());
}
