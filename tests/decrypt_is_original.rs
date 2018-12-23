use std::io::Cursor;

const TEST_DATA: &'static[u8] = b"Hello, yes I'll be used for this test!";

#[test]
fn decrypt_is_orignal(){
    test(delta_l::ZeroOffset)
}

#[test]
fn decrypt_is_orignal_with_password(){
    test(delta_l::PassHashOffsetter::new("hejsa!"))
}

fn test<T: Copy + delta_l::Offset>(passhash: T) {
    let test_data = TEST_DATA.to_vec();

    let mut encrypted_data = Cursor::new(Vec::with_capacity(TEST_DATA.len() + 12));
    delta_l::encode_with_checksum(passhash, &mut &*test_data, &mut encrypted_data).unwrap();
    encrypted_data.set_position(0);

    let mut dec_vec = Vec::with_capacity(TEST_DATA.len());
    delta_l::decode(passhash, &mut encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(TEST_DATA, &*dec_vec)
}
