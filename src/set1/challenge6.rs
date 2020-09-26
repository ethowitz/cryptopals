use std::fs;
use std::cmp::Ordering;
use std::convert::TryFrom;
use super::challenge1::Base64;
use super::challenge2;
use super::challenge3;
use super::challenge5;

fn get_hamming_distance(buffer1: &[u8], buffer2: &[u8]) -> Result<usize, &'static str> {
    let count_bits = |byte| (0..8).fold(0, |acc, n| acc + (((0x01 << n) & byte) >> n) as usize);

    challenge2::xor(buffer1, buffer2).map(|buffer| {
        buffer.iter().fold(0, |acc, byte| acc + count_bits(*byte))
    })
}

fn find_key(buffer: &[u8]) -> Vec<u8> {
    const MAX_KEYSIZE: usize = 40;

    let keysize = (1..MAX_KEYSIZE).min_by(|keysize1, keysize2| {
        let keysize1_hamming_distance = get_hamming_distance(&buffer[..*keysize1],
            &buffer[*keysize1..*keysize1*2]).unwrap();
        let normalized_keysize1_hamming_distance =
            keysize1_hamming_distance as f64 / *keysize1 as f64;

        let keysize2_hamming_distance = get_hamming_distance(&buffer[..*keysize2],
            &buffer[*keysize2..*keysize2*2]).unwrap();
        let normalized_keysize2_hamming_distance =
            keysize2_hamming_distance as f64 / *keysize2 as f64;

        if normalized_keysize1_hamming_distance > normalized_keysize2_hamming_distance {
            Ordering::Greater 
        } else if normalized_keysize1_hamming_distance < normalized_keysize2_hamming_distance {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }).unwrap();
    
    let blocks = buffer.chunks(keysize);
    let transposed_blocks = (0..blocks.len())
        .map(|n: usize| -> Vec<u8> { blocks.clone().map(|block| block[n]).collect() });

    transposed_blocks
        .take(keysize)
        .map(|block| challenge3::find_key(&block)[0])
        .collect()
}

// INTUITION
// 1. finding the keysize and transposing the blocks gives you blocks of bytes that were all
//    XOR'd with the same byte
// 2. once we have the single-character key for each transposed block, we can un-transpose one
//    "cycle" of keys to get the original key
// *  This approach makes cryptanalysis easier because we create blocks of bytes whose letter 
//    frequencies don't change with the application of the key
// ?  Why does the hamming distance trick work?
fn find_plaintext(buffer: &[u8]) -> Vec<u8> {
    let key = find_key(buffer);
    challenge5::repeating_key_xor(&key, buffer)
}

#[test]
fn test_get_hamming_distance() {
    let buffer1 = "this is a test".as_bytes();
    let buffer2 = "wokka wokka!!!".as_bytes();
    let expected_hamming_distance = 37;
    assert_eq!(expected_hamming_distance, get_hamming_distance(buffer1, buffer2).unwrap());
}

#[test]
fn verify() {
    let raw = fs::read_to_string("./src/set1/6.txt").unwrap();
    let base64 = Base64::try_from(raw.replace("\n", "").as_str()).unwrap();
    let plaintext = String::from_utf8(find_plaintext(&base64.to_bytes())).unwrap();

    assert_eq!(plaintext, "");
}
