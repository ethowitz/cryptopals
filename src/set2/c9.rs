use crate::helpers;

#[test]
fn verify() {
    let expected_output = "YELLOW SUBMARINE\x04\x04\x04\x04";
    let padded = helpers::pkcs7_pad("YELLOW SUBMARINE".as_bytes(), 20);
    assert_eq!(expected_output.as_bytes(), padded);
}
