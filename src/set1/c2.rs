use crate::helpers::{self, Hex};
use std::convert::TryFrom;

#[test]
fn verify() {
    let operand1 = Hex::try_from("1c0111001f010100061a024b53535009181c").unwrap();
    let operand2 = Hex::try_from("686974207468652062756c6c277320657965").unwrap();

    let raw_result = helpers::xor(
        operand1.to_bytes().as_slice(),
        operand2.to_bytes().as_slice(),
    )
    .unwrap();
    let result = Hex::from_bytes(raw_result.as_slice());
    let expected_result = "746865206b696420646f6e277420706c6179";
    assert_eq!(result.to_string(), expected_result);
}
