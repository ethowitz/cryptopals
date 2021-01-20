use crate::block_ciphers::{Aes, Input, Mode};
use crate::helpers::Base64;
use crate::set1::{c5, c6};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn ciphertexts() -> Vec<Vec<u8>> {
    fn read_lines<P: AsRef<Path>>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }
    let lines = read_lines("./src/set3/20.txt").unwrap();

    let plaintexts: Vec<Vec<u8>> = lines
        .map(|line| Base64::try_from(line.unwrap().as_str()).unwrap().to_bytes())
        .collect();

    let mut key = [0u8; Aes::BLOCK_SIZE];
    for i in 0..Aes::BLOCK_SIZE {
        key[i] = rand::random::<u8>()
    }

    let mut aes = Aes::new(key, Mode::Ctr);

    plaintexts
        .iter()
        .map(|plaintext| aes.encrypt(plaintext, Input::Nonce(0)).unwrap())
        .collect()
}

fn attack(ciphertexts: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    let min_len = ciphertexts
        .iter()
        .min_by(|x, y| x.len().cmp(&y.len()))
        .unwrap()
        .len();
    let truncated_ciphertexts: Vec<Vec<u8>> = ciphertexts
        .iter()
        .map(|ctxt| ctxt[..min_len].to_vec())
        .collect();

    let keystream = c6::find_key(&truncated_ciphertexts.concat(), min_len);

    truncated_ciphertexts
        .iter()
        .map(|ctxt| c5::repeating_key_xor(&keystream, ctxt))
        .collect()
}

#[test]
fn verify() {
    let ciphertexts = ciphertexts();
    let plaintexts = attack(ciphertexts);

    // Because this attack is imperfect, the plaintexts will not be 100% correct and their values
    // will not be consistent
    for plaintext in plaintexts {
        println!("{}", String::from_utf8_lossy(&plaintext));
    }
}
