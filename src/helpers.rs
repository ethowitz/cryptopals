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
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct Base64(Vec<u8>);

impl Base64 {
    pub fn to_bytes(&self) -> Vec<u8> {
        let get_original_value = |byte: &u8| {
            let uppercase_letter_range = {
                let ascii_code = 'A' as u8;
                ascii_code..(ascii_code + 26)
            };
            let lowercase_letter_range = {
                let ascii_code = 'a' as u8;
                ascii_code..(ascii_code + 26)
            };
            let number_range = {
                let zero_ascii_code = '0' as u8;
                zero_ascii_code..(zero_ascii_code + 10)
            };

            if uppercase_letter_range.contains(byte) {
                byte - ('A' as u8)
            } else if lowercase_letter_range.contains(byte) {
                byte - ('a' as u8) + 26
            } else if number_range.contains(byte) {
                byte - ('0' as u8) + 52
            } else if *byte == ('+' as u8) {
                62
            } else if *byte == ('/' as u8) {
                63
            } else {
                println!("{}", byte);
                panic!("we should never get to this scenario given the bit operations above")
            }
        };

        let mut v = Vec::new();

        for chunk in self.0.chunks(4) {
            let number_of_pads = chunk.iter().filter(|byte| **byte as char == '=').count();

            if number_of_pads == 0 {
                let original_values: Vec<u8> = chunk.iter().map(get_original_value).collect();

                let combined: u32 = (original_values[0] as u32) << 18
                    | (original_values[1] as u32) << 12
                    | (original_values[2] as u32) << 6
                    | original_values[3] as u32;

                v.push(((combined & 0xFF0000) >> 16) as u8);
                v.push(((combined & 0xFF00) >> 8) as u8);
                v.push((combined & 0xFF) as u8);
            } else if number_of_pads == 1 {
                let original_value1 = get_original_value(&chunk[0]);
                let original_value2 = get_original_value(&chunk[1]);
                let original_value3 = get_original_value(&chunk[2]);

                v.push(original_value1 << 2 | original_value2 >> 4);
                v.push(original_value2 << 4 | original_value3 >> 2);
            } else if number_of_pads == 2 {
                let original_value1 = get_original_value(&chunk[0]);
                let original_value2 = get_original_value(&chunk[1]);
                v.push(original_value1 << 2 | original_value2 >> 4);
            }
        }

        v
    }
}

impl From<&[u8]> for Base64 {
    fn from(bytes: &[u8]) -> Self {
        let get_ascii_value = |index: u32| {
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

        let get_inner_groups = |slice: &[u8]| {
            let outer_group: u32 =
                (slice[0] as u32) << 16 | (slice[1] as u32) << 8 | slice[2] as u32;
            let mask = 0b00111111;
            let index1 = (outer_group & (mask << 18)) >> 18;
            let index2 = (outer_group & (mask << 12)) >> 12;
            let index3 = (outer_group & (mask << 6)) >> 6;
            let index4 = outer_group & mask;

            vec![
                get_ascii_value(index1),
                get_ascii_value(index2),
                get_ascii_value(index3),
                get_ascii_value(index4),
            ]
        };

        let length = bytes.len();
        let mut last_quantum = {
            let remaining_bytes: Vec<u8> = bytes
                .iter()
                .rev()
                .take(length % 3)
                .rev()
                .map(|n| *n)
                .collect();

            let mut v = Vec::new();

            if remaining_bytes.len() == 1 {
                let inner_group_1 = (remaining_bytes[0] & 0b11111100) >> 2;
                let inner_group_2 = (remaining_bytes[0] & 0b00000011) << 4;

                v.push(get_ascii_value(inner_group_1 as u32));
                v.push(get_ascii_value(inner_group_2 as u32));
                v.push('=' as u8);
                v.push('=' as u8);
            } else if remaining_bytes.len() == 2 {
                let outer_group = (remaining_bytes[0] as u32) << 8 | (remaining_bytes[1] as u32);
                let mask = 0b00111111;
                let inner_group_1 = (outer_group & (mask << 10)) >> 10;
                let inner_group_2 = (outer_group & (mask << 4)) >> 4;
                let inner_group_3 = (outer_group & mask) << 2;

                v.push(get_ascii_value(inner_group_1));
                v.push(get_ascii_value(inner_group_2));
                v.push(get_ascii_value(inner_group_3));
                v.push('=' as u8);
            }

            v
        };

        let mut output_bytes: Vec<u8> = bytes
            .chunks(3 as usize)
            .take(length - (length % 3))
            .flat_map(|slice| get_inner_groups(slice))
            .collect();

        output_bytes.append(&mut last_quantum);

        Self(output_bytes)
    }
}

impl TryFrom<&str> for Base64 {
    type Error = &'static str;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        let mut v = Vec::new();

        fn is_valid_base64_character(c: char) -> bool {
            let uppercase_letter_range = {
                let ascii_code = 'A' as u8;
                ascii_code..(ascii_code + 26)
            };
            let lowercase_letter_range = {
                let ascii_code = 'a' as u8;
                ascii_code..(ascii_code + 26)
            };
            let number_range = {
                let zero_ascii_code = '0' as u8;
                zero_ascii_code..(zero_ascii_code + 10)
            };
            let special_characters = ['+', '/', '='];
            let n = c as u8;

            uppercase_letter_range.contains(&n)
                || lowercase_letter_range.contains(&n)
                || number_range.contains(&n)
                || special_characters.contains(&c)
        }

        for c in string.chars() {
            if is_valid_base64_character(c) {
                v.push(c as u8)
            } else {
                return Err("invalid base64!");
            }
        }

        Ok(Base64(v))
    }
}

impl fmt::Display for Base64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{}", *byte as char)?
        }

        Ok(())
    }
}

pub fn xor(buffer1: &[u8], buffer2: &[u8]) -> Result<Vec<u8>, &'static str> {
    if buffer1.len() == buffer2.len() {
        let mut out = Vec::new();

        for (byte1, byte2) in buffer1.iter().zip(buffer2.iter()) {
            out.push(byte1 ^ byte2);
        }

        Ok(out)
    } else {
        Err("buffers must be of equal length")
    }
}

pub fn pkcs7_pad(buffer: &[u8], block_size: usize) -> Vec<u8> {
    let pad_start = buffer.len() % block_size;
    let pad = block_size - pad_start;
    let mut padded = buffer.to_vec();

    for _ in 0..pad {
        padded.push(pad as u8)
    }

    padded
}

pub fn pkcs7_unpad(buffer: &[u8], block_size: usize) -> Option<Vec<u8>> {
    if buffer.len() % block_size == 0 {
        let blocks = buffer.chunks(block_size);
        let length = blocks.len();

        if blocks.clone().last().unwrap() == vec![block_size as u8; block_size] {
            Some(blocks.take(length - 1).flatten().cloned().collect())
        } else {
            let unpadded_last_block = {
                let mut last_block = blocks.clone().last().unwrap().to_vec();
                let pad_byte = last_block[last_block.len() - 1];
                let number_of_pad_bytes = last_block
                    .iter()
                    .rev()
                    .take_while(|byte| **byte == pad_byte)
                    .count();

                if &last_block[block_size - number_of_pad_bytes..]
                    != vec![number_of_pad_bytes as u8; number_of_pad_bytes]
                {
                    return None;
                }

                last_block.truncate(block_size - number_of_pad_bytes);
                last_block
            };
            let mut output: Vec<Vec<u8>> = blocks.take(length - 1).map(|x| x.to_vec()).collect();

            output.push(unpadded_last_block);
            Some(output.iter().flatten().cloned().collect())
        }
    } else {
        None
    }
}
