use std::io::Cursor;

const TEST_DATA: &'static[u8] = include_bytes!("data/test_data.bin");

const TEST_DATA_DELTA: &'static[u8] = include_bytes!("data/test_data.bin.delta");
const TEST_DATA_DELTA_DEC: &'static[u8] = include_bytes!("data/test_data.bin.delta.dec");

const TEST_DATA_DELTA_NOC: &'static[u8] = include_bytes!("data/test_data.bin.delta-noc");
const TEST_DATA_DELTA_NOC_DEC: &'static[u8] = include_bytes!("data/test_data.bin.delta-noc.dec");

const TEST_DATA_DELTA_PASS: &'static[u8] = include_bytes!("data/test_data.bin.delta-pass");
const TEST_DATA_DELTA_PASS_DEC: &'static[u8] = include_bytes!("data/test_data.bin.delta-pass.dec");

const TEST_DATA_DELTA_PASS_NOC: &'static[u8] = include_bytes!("data/test_data.bin.delta-pass-noc");
const TEST_DATA_DELTA_PASS_NOC_DEC: &'static[u8] = include_bytes!("data/test_data.bin.delta-pass-noc.dec");

#[test]
fn test_normal(){
    let test_data = TEST_DATA;
    let mut encrypted_data = Cursor::new(Vec::new());

    delta_l::encode_with_checksum([0; 8], &mut &*test_data, &mut encrypted_data).unwrap();
    encrypted_data.set_position(0);
    assert_eq!(*encrypted_data.get_ref(), TEST_DATA_DELTA);

    let mut dec_vec = Vec::new();
    delta_l::decode([0; 8], &mut encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(dec_vec, test_data);
    assert_eq!(dec_vec, TEST_DATA_DELTA_DEC);
}
#[test]
fn test_no_checksum(){
    let test_data = TEST_DATA;
    let mut encrypted_data = Vec::new();

    delta_l::encode_no_checksum([0; 8], &mut &*test_data, &mut encrypted_data).unwrap();
    assert_eq!(encrypted_data, TEST_DATA_DELTA_NOC);

    let mut dec_vec = Vec::new();
    delta_l::decode([0; 8], &mut &*encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(dec_vec, test_data);
    assert_eq!(dec_vec, TEST_DATA_DELTA_NOC_DEC);
}

#[test]
fn test_normal_with_pass(){
    let passhash = delta_l::get_passhash("SECRET");

    let test_data = TEST_DATA;
    let mut encrypted_data = Cursor::new(Vec::new());

    delta_l::encode_with_checksum(passhash, &mut &*test_data, &mut encrypted_data).unwrap();
    encrypted_data.set_position(0);
    assert_eq!(*encrypted_data.get_ref(), TEST_DATA_DELTA_PASS);

    let mut dec_vec = Vec::new();
    delta_l::decode(passhash, &mut encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(dec_vec, test_data);
    assert_eq!(dec_vec, TEST_DATA_DELTA_PASS_DEC);
}
#[test]
fn test_no_checksum_with_pass(){
    let passhash = delta_l::get_passhash("SECRET");

    let test_data = TEST_DATA;
    let mut encrypted_data = Vec::new();

    delta_l::encode_no_checksum(passhash, &mut &*test_data, &mut encrypted_data).unwrap();
    assert_eq!(encrypted_data, TEST_DATA_DELTA_PASS_NOC);

    let mut dec_vec = Vec::new();
    delta_l::decode(passhash, &mut &*encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(dec_vec, test_data);
    assert_eq!(dec_vec, TEST_DATA_DELTA_PASS_NOC_DEC);
}
