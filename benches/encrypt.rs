#![cfg(feature = "nightly")]
#![feature(test)]

extern crate test;
extern crate delta_l as dl;

use std::io::{Write, Seek, SeekFrom, Result};

const TEST_DATA: &'static[u8] = include_bytes!("../test_data/bench.txt");
const TEST_DATA_DELTA: &'static[u8] = include_bytes!("../test_data/bench.txt.delta");
const TEST_DATA_DELTA_NOC: &'static[u8] = include_bytes!("../test_data/bench.txt.delta-noc");

#[derive(Default, Debug, Clone)]
struct SeekableSink(());

impl Write for SeekableSink {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize> { Ok(buf.len()) }
    #[inline]
    fn flush(&mut self) -> Result<()> { Ok(()) }
}

impl Seek for SeekableSink {
    fn seek(&mut self, _: SeekFrom) -> Result<u64> {
        Ok(0)
    }
}

fn def() -> delta_l::PassHashOffsetter {
    Default::default()
}


#[bench]
fn encrypt(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::encode_with_checksum(def(), &mut TEST_DATA, &mut SeekableSink::default())).unwrap());
}

#[bench]
fn encrypt_no_checksum(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::encode_no_checksum(def(), &mut TEST_DATA, &mut SeekableSink::default())).unwrap());
}

#[bench]
fn decrypt(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::decode(def(), &mut TEST_DATA_DELTA, &mut SeekableSink::default())).unwrap());
}

#[bench]
fn decrypt_no_checksum(b: &mut test::Bencher){
    b.iter(|| test::black_box(dl::decode(def(), &mut TEST_DATA_DELTA_NOC, &mut SeekableSink::default())).unwrap());
}
