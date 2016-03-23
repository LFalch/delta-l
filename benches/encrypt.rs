#![feature(test)]

extern crate test;
extern crate delta_l;

use delta_l::{DeltaL, Mode};

use std::fs::File;
use std::io::Write;

#[bench]
fn encrypt(b: &mut test::Bencher){
    let f = File::open("test_data/bench.txt").unwrap();
    let dl = DeltaL::new(Mode::Encrypt{checksum: true});

    b.iter(|| dl.execute(&f).unwrap());
}

fn save(res_vec: Vec<u8>, to_path: &str) -> std::io::Result<()>{
    let mut result_file = try!(File::create(to_path));

    result_file.write_all(&res_vec)
}

#[bench]
fn decrypt(b: &mut test::Bencher){
    let file = File::open("test_data/bench.txt").unwrap();
    let save_path = "test_data/bench.txt.delta";
    save(DeltaL::new(Mode::Encrypt{checksum: true}).execute(file).unwrap(), save_path).unwrap();

    let dl = DeltaL::new(Mode::Decrypt);
    let f = File::open(save_path).unwrap();

    b.iter(|| dl.execute(&f).unwrap());
}
