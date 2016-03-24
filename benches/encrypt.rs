#![feature(test)]

extern crate test;
extern crate delta_l;

use delta_l::DeltaL;

use std::fs::File;
use std::io::sink;

#[bench]
fn encrypt(b: &mut test::Bencher){
    let mut f = File::open("test_data/bench.txt").unwrap();
    let dl = DeltaL::new();

    b.iter(|| dl.encode(&mut f, &mut sink(), true).unwrap());
}

#[bench]
fn decrypt(b: &mut test::Bencher){
    let dl = DeltaL::new();

    let mut file = File::open("test_data/bench.txt").unwrap();

    let mut enc_data = Vec::new();
    dl.encode(&mut file, &mut enc_data, true).unwrap();

    b.iter(|| dl.decode(&mut &*enc_data, &mut sink()).unwrap());
}
