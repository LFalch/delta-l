#![cfg(feature = "nightly")]
#![feature(test)]

extern crate test;
extern crate delta_l as dl;

use std::io::sink;

const TEST_DATA: &'static[u8] = include_bytes!("../test_data/bench.txt");
const TEST_DATA_DELTA: &'static[u8] = include_bytes!("../test_data/bench.txt.delta");

#[bench]
fn encrypt(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::encode_with_checksum([0; 8], &mut TEST_DATA, &mut sink())).unwrap());
}

#[bench]
fn decrypt(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::decode([0; 8], &mut TEST_DATA_DELTA, &mut sink())).unwrap());
}
