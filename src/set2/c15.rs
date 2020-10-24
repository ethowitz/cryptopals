use crate::helpers;

#[test]
fn verify() {
    assert_eq!(Some(b"ICE ICE BABY".to_vec()),
        helpers::pkcs7_unpad(b"ICE ICE BABY\x04\x04\x04\x04", 16));
    assert_eq!(None, helpers::pkcs7_unpad(b"ICE ICE BABY\x05\x05\x05\x05", 16));
    assert_eq!(None, helpers::pkcs7_unpad(b"ICE ICE BABY\x01\x02\x03\x04", 16));
}
