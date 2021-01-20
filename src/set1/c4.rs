use super::c3;
use crate::helpers::{self, Hex};
use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn find_plaintext<P: AsRef<Path>>(filename: P) -> Vec<u8> {
    fn read_lines<P: AsRef<Path>>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    let lines = read_lines(filename).unwrap().filter_map(Result::ok);
    let ciphertexts: Vec<Vec<u8>> = lines
        .map(|hex| Hex::try_from(hex.as_str()).unwrap().to_bytes())
        .collect();

    let plaintexts_iter = ciphertexts
        .iter()
        .flat_map(|ciphertext: &Vec<u8>| -> Vec<Vec<u8>> {
            (0..u8::MAX)
                .map(|n| helpers::xor(&ciphertext, &vec![n; ciphertext.len()]).unwrap())
                .collect()
        });

    plaintexts_iter
        .min_by(|plaintext1, plaintext2| {
            if c3::get_score(&plaintext1) > c3::get_score(&plaintext2) {
                Ordering::Greater
            } else {
                Ordering::Less
            }
        })
        .unwrap()
        .clone()
}

#[test]
fn verify() {
    let plaintext = find_plaintext("./src/set1/4.txt");
    assert_eq!(
        String::from_utf8(plaintext).unwrap().as_str(),
        "Now that the party is jumping\n"
    )
}
