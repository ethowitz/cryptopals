use crate::block_ciphers::{Aes, Mode};
use crate::set1::c7;
use rand::{distributions::Uniform, Rng};
use super::c10;

const AES_128_BLOCK_SIZE: usize = 16;

struct Oracle {
    cbc: Aes,
    ecb: Aes,
}

impl Oracle {
    fn new() -> Self {
        let mut key = [0u8; Aes::BLOCK_SIZE];
        for i in 0..Aes::BLOCK_SIZE { key[i] = rand::random::<u8>() }

        let cbc = Aes::new(key, Mode::Cbc);
        let ecb = Aes::new(key, Mode::Ecb);

        Self { cbc, ecb }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let plaintext: Vec<u8> = {
            let pad_bytes_range = Uniform::new(5, 10);
            let mut head_bytes = Self::random_bytes(rng.sample(&pad_bytes_range));
            let mut tail_bytes = Self::random_bytes(rng.sample(&pad_bytes_range));

            let mut p = Vec::new();
            p.append(&mut head_bytes);
            p.append(&mut plaintext.to_vec());
            p.append(&mut tail_bytes);

            p
        };

        if rng.sample(Uniform::new(0, 2)) == 0 {
            let mut iv = [0u8; Aes::BLOCK_SIZE];
            for i in 0..Aes::BLOCK_SIZE { iv[i] = rand::random::<u8>() }

            self.cbc.encrypt(plaintext, Some(iv)).unwrap()
        } else {
            self.ecb.encrypt(plaintext, None).unwrap()
        }
    }

    fn random_bytes(n: usize) -> Vec<u8> {
        (0..n).map(|_| rand::random::<u8>()).collect::<Vec<u8>>()
    }
}


pub enum AesMode {
    Cbc,
    Ecb,
}

pub fn aes_detection_oracle<F>(mut encrypter: F) -> AesMode
    where F: FnMut(&[u8]) -> Vec<u8>
{
    // choose any plaintext such that the first two blocks are equal
    let chosen_plaintext = [0u8; u8::MAX as usize];
    let ciphertext = encrypter(&chosen_plaintext);
    let ciphertext_blocks: Vec<&[u8]> = ciphertext
        .chunks(Aes::BLOCK_SIZE)
        .collect();

    // if the first two ciphertext blocks are the same, ECB is being used
    if ciphertext_blocks[1] == ciphertext_blocks[2] {
        AesMode::Ecb
    } else {
        AesMode::Cbc
    }
}

#[test]
fn verify() {
    let epsilon = 0.01;
    let num_trials = 50000;
    let mut oracle = Oracle::new();

    let sum = (0..num_trials).fold(0, |acc, _| {
        acc + match aes_detection_oracle(|plaintext| oracle.encrypt(plaintext)) {
            AesMode::Cbc => 0,
            AesMode::Ecb => 1
        }
    });

    let average = sum as f64 / num_trials as f64;
    println!("{}", average);

    assert!(0.5 - epsilon < average && average < 0.5 + epsilon);
}
