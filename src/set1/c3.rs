use std::cmp::Ordering;
use std::collections::HashMap;
use std::convert::TryFrom;
use super::c2;
use super::c1::Hex;

// Public
pub fn get_char_distribution(buffer: &[u8]) -> HashMap<char, f64> {
    let mut distribution = HashMap::new();

    for c in buffer.iter().map(|byte| *byte as char) {
        let count = distribution.entry(c).or_insert(0.0);
        *count += 1.0;
    }

    let length = buffer.len() as f64;
    for count in distribution.values_mut() { *count *= 100f64 / length };

    distribution
}

// Private
lazy_static! {
    pub static ref FREQUENCY_TABLE: HashMap<char, f64> = {
        let mut table = HashMap::new();

        table.insert('e', 12.02);
        table.insert('t', 9.10);
        table.insert('a', 8.12);
        table.insert('o', 7.68);
        table.insert('i', 7.31);
        table.insert('n', 6.95);
        table.insert('s', 6.28);
        table.insert('r', 6.02);
        table.insert('h', 5.92);
        table.insert('d', 4.32);
        table.insert('l', 3.98);
        table.insert('u', 2.88);
        table.insert('c', 2.71);
        table.insert('m', 2.61);
        table.insert('f', 2.30);
        table.insert('y', 2.11);
        table.insert('w', 2.09);
        table.insert('g', 2.03);
        table.insert('p', 1.82);
        table.insert('b', 1.49);
        table.insert('v', 1.11);
        table.insert('k', 0.69);
        table.insert('x', 0.17);
        table.insert('q', 0.11);
        table.insert('j', 0.10);
        table.insert('z', 0.07);

        table
    };
}

pub fn get_score(buffer: &[u8]) -> f64 {
    let char_distribution = get_char_distribution(buffer);

    let distances_iter = FREQUENCY_TABLE.iter().map(|(letter, expected_frequency)| {
        char_distribution
            .get(letter)
            .map(|freq| (freq - expected_frequency).abs())
            .unwrap_or(*expected_frequency)
    });

    distances_iter.sum::<f64>() / FREQUENCY_TABLE.len() as f64
}

pub fn find_key(ciphertext: &[u8]) -> Vec<u8> {
    let length = ciphertext.len();

    (0..u8::MAX)
        .map(|n| vec![n; length])
        .min_by(|key1, key2| {
            let plaintext1 = c2::xor(ciphertext, key1).unwrap();
            let score1 = get_score(&plaintext1);
            let plaintext2 = c2::xor(ciphertext, key2).unwrap();
            let score2 = get_score(&plaintext2);

            score1.partial_cmp(&score2).unwrap_or(Ordering::Equal)
        })
        .unwrap()
}

pub fn find_plaintext(ciphertext: &[u8]) -> Vec<u8> {
    let key = find_key(ciphertext);

    c2::xor(&key, ciphertext).unwrap()
}

#[test]
fn verify() {
    let ciphertext = Hex::try_from("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393\
        b3736").unwrap();

    let plaintext = find_plaintext(ciphertext.to_bytes().as_slice());
    assert_eq!(String::from_utf8(plaintext).unwrap().as_str()
        , "Cooking MC\'s like a pound of bacon");
}
