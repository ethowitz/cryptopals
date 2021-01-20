use crate::helpers::{Base64, Hex};
use std::convert::TryFrom;

#[test]
fn verify() {
    let raw_hex =
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f757320\
        6d757368726f6f6d";

    let hex = Hex::try_from(raw_hex).unwrap();
    assert_eq!(hex.to_string(), raw_hex);

    let bytes = hex.to_bytes();
    let base64 = Base64::from(bytes.as_slice());

    assert_eq!(
        base64.to_string(),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );

    let expected_base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    assert_eq!(
        Base64::try_from(expected_base64).unwrap().to_string(),
        expected_base64
    );

    let bytes = base64.to_bytes();
    let new_hex = Hex::from_bytes(&bytes);
    assert_eq!(new_hex.to_string(), raw_hex);

    let hex3 = Hex::try_from("66").unwrap().to_bytes();
    let base642 = Base64::from(hex3.as_slice()).to_string();
    assert_eq!(base642, "Zg==");

    assert_eq!(
        Base64::try_from("Zg==").unwrap().to_bytes(),
        vec!['f' as u8]
    );
    assert_eq!(
        Base64::try_from("bXkgbmFtZSBpcyBldGhhbg==")
            .unwrap()
            .to_bytes(),
        "my name is ethan".as_bytes()
    );
}
