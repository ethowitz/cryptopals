use super::c1::Hex;

pub fn repeating_key_xor(key: &[u8], buffer: &[u8]) -> Vec<u8> {
    key.iter().cycle().zip(buffer.iter()).map(|(byte1, byte2)| byte1 ^ byte2).collect()
}

#[test]
fn verify() {
    let plaintext = "Burning 'em, if you ain't quick and nimble\n\
        I go crazy when I hear a cymbal";
    let key = "ICE";
    let ciphertext = repeating_key_xor(key.as_bytes(), plaintext.as_bytes());
    let ciphertext_hex = Hex::from_bytes(&ciphertext).to_string();

    let expected_ciphertext = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427\
        2765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(ciphertext_hex, expected_ciphertext);
}
