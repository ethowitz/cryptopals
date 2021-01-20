use crate::block_ciphers::{Aes, Input, Mode};
use crate::helpers::Base64;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

fn ciphertexts() -> Vec<Vec<u8>>{
    fn read_lines<P: AsRef<Path>>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>> {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }
    let lines = read_lines("./src/set3/19.txt").unwrap();

    let plaintexts: Vec<Vec<u8>> = lines
        .map(|line| Base64::try_from(line.unwrap().as_str()).unwrap().to_bytes())
        .collect();

    let mut key = [0u8; Aes::BLOCK_SIZE];
    for i in 0..Aes::BLOCK_SIZE {
        key[i] = rand::random::<u8>()
    }

    let mut aes = Aes::new(key, Mode::Ctr);
    
    plaintexts.iter()
        .map(|plaintext| aes.encrypt(plaintext, Input::Nonce(0)).unwrap())
        .collect()
}

fn attack(ciphertexts: &[&[u8]]) -> Vec<Vec<u8>> {

}

#[test]
fn verify() {
    let ciphertexts = ciphertexts();

    assert_eq!(
        b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby ",
        plaintext.as_slice()
    );
}
