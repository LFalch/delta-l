extern crate delta_l as dl;

const TEST_DATA: &'static[u8] = b"Hello, yes I'll be used for this test!";

#[test]
fn decrypt_is_orignal(){
    test([0; 8])
}

#[test]
fn decrypt_is_orignal_with_password(){
    test(dl::get_passhash("hejsa!"))
}

fn test(passhash: [u8; 8]) {
    let test_data = TEST_DATA.to_vec();

    let mut encrypted_data = Vec::with_capacity(TEST_DATA.len() + 12);
    dl::encode_with_checksum(passhash, &mut &*test_data, &mut encrypted_data).unwrap();

    let mut dec_vec = Vec::with_capacity(TEST_DATA.len());
    dl::decode(passhash, &mut &*encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(TEST_DATA, &*dec_vec)
}
