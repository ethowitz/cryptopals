use super::c9;

pub fn pkcs7_unpad(buffer: &[u8], block_size: u8) -> Option<Vec<u8>> {
    c9::pkcs7_unpad(buffer, block_size)
}

#[test]
fn verify() {
    assert_eq!(Some(b"ICE ICE BABY".to_vec()), pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16));
    assert_eq!(None, pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16));
    assert_eq!(None, pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16));
}
