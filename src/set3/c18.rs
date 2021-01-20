use crate::block_ciphers::{Aes, Input, Mode};
use crate::helpers::Base64;
use std::convert::TryFrom;

#[test]
fn verify() {
    let ciphertext = Base64::try_from(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX\
        0KSvoOLSFQ==",
    )
    .unwrap()
    .to_bytes();
    let mut aes = Aes::new(b"YELLOW SUBMARINE".clone(), Mode::Ctr);
    let plaintext = aes.decrypt(ciphertext, Input::Nonce(0)).unwrap();

    assert_eq!(
        b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ",
        plaintext.as_slice()
    );
}
