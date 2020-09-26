use std::convert::TryFrom;
use std::fmt;

pub struct Hex(Vec<u8>);

impl Hex {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Hex(bytes.to_vec())
    }
}

impl TryFrom<&str> for Hex {
    type Error = &'static str;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        let mut hex = Vec::new();

        let mut prev_nibble = 0u8;
        for (i, c) in s.char_indices() {
            let digit = c.to_digit(16).ok_or("invalid hex!")? as u8;

            if i % 2 == 0 {
                prev_nibble = digit;
            } else {
                hex.push((prev_nibble << 4) | digit);
            }
        }

        Ok(Hex(hex))
    }
}

impl fmt::Display for Hex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 { write!(f, "{:x}", byte)? }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Base64(Vec<u8>);

impl Base64 {
    const INNER_GROUP_SIZE_BITS: u8 = 6;
    const OUTER_GROUP_SIZE_BITS: u8 = 24;
    const SIZE_U8_BITS: u8 = 8;
}

impl From<&[u8]> for Base64 {
    fn from(bytes: &[u8]) -> Self {
        let get_inner_groups = |slice: &[u8]| {
            let outer_group: u32 = (slice[0] as u32) << 16
                | (slice[1] as u32) << 8
                | slice[2] as u32;
            let mask = 0b00111111u32;
            let get_ascii_value = |inner_group_number: u8| {
                let offset = Self::INNER_GROUP_SIZE_BITS * inner_group_number;
                let index = (outer_group & (mask << offset)) >> offset;

                if (0..26).contains(&index) {
                    (index + ('A' as u32)) as u8
                } else if (26..52).contains(&index) {
                    (index + ('a' as u32) - 26) as u8
                } else if (52..62).contains(&index) {
                    (index + ('0' as u32) - 52) as u8
                } else if index == 62 {
                    '+' as u8
                } else if index == 63 {
                    '/' as u8
                } else {
                    panic!("we should never get to this scenario given the bit operations above")
                }
            };

            vec![get_ascii_value(3), get_ascii_value(2), get_ascii_value(1), get_ascii_value(0)]
        };

        let output_bytes = bytes
            .chunks((Self::OUTER_GROUP_SIZE_BITS / Self::SIZE_U8_BITS) as usize)
            .flat_map(|slice| get_inner_groups(slice))
            .collect();

        Self(output_bytes)
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 { write!(f, "{}", *byte as char)? }

        Ok(())
    }
}

#[test]
fn verify() {
    let raw_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f757320\
        6d757368726f6f6d";

    let hex = Hex::try_from(raw_hex).unwrap();
    assert_eq!(hex.to_string(), raw_hex);

    let bytes = hex.to_bytes();
    let base64 = Base64::from(bytes.as_slice());
    
    assert_eq!(base64.to_string(), "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t");
}

