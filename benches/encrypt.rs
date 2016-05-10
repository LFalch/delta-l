#![cfg(feature = "nightly")]
#![feature(test)]

extern crate test;
extern crate delta_l as dl;

use std::fs::File;
use std::io::sink;

#[bench]
fn encrypt(b: &mut test::Bencher){
    let mut f = File::open("test_data/bench.txt").unwrap();

    b.iter(|| dl::encode_with_checksum([0; 8], &mut f, &mut sink()).unwrap());
}

#[bench]
fn decrypt(b: &mut test::Bencher){
    let mut file = File::open("test_data/bench.txt").unwrap();

    let mut enc_data = Vec::new();
    dl::encode_with_checksum([0; 8], &mut file, &mut enc_data).unwrap();

    b.iter(|| dl::decode([0; 8], &mut &*enc_data, &mut sink()).unwrap());
}
