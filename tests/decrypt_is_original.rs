use delta_l::DeltaL;

const TEST_DATA: &'static[u8] = b"Hello, yes I'll be used for this test!";

#[test]
fn decrypt_is_orignal(){
    let dl = DeltaL::new();
    let test_data = TEST_DATA.to_vec();
    let mut encrypted_data = Vec::new();

    dl.encode(&mut &*test_data, &mut encrypted_data, true).unwrap();

    let mut dec_vec = Vec::new();
    dl.decode(&mut &*encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(test_data, &*dec_vec);
}

#[test]
fn decrypt_is_orignal_with_password(){
    let mut dl = DeltaL::new();

    dl.set_passphrase("hejsa!");

    let test_data = TEST_DATA.to_vec();

    let mut encrypted_data = Vec::new();

    dl.encode(&mut &*test_data, &mut encrypted_data, true).unwrap();

    let mut dec_vec = Vec::new();
    dl.decode(&mut &*encrypted_data, &mut dec_vec).unwrap();

    assert_eq!(test_data, &*dec_vec);
}
