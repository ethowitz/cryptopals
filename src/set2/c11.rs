use crate::set1::c7;
use rand::{distributions::Uniform, Rng};
use super::c10;

const AES_128_BLOCK_SIZE: usize = 16;

pub fn aes_encryption_oracle(buffer: &[u8]) -> Vec<u8> {
    let gen_bytes = |n| {
        (0..n).map(|_| rand::random::<u8>())
    };

    let mut rng = rand::thread_rng();
    let plaintext: Vec<u8> = {
        let pad_bytes_range = Uniform::new(5, 10);
        let head_bytes = gen_bytes(rng.sample(&pad_bytes_range));
        let tail_bytes = gen_bytes(rng.sample(&pad_bytes_range));

        head_bytes
            .chain(buffer.iter().copied())
            .chain(tail_bytes)
            .collect()
    };

    let key: Vec<u8> = gen_bytes(AES_128_BLOCK_SIZE).collect();
    if rng.sample(Uniform::new(0, 2)) == 0 {
        let iv: Vec<u8> = gen_bytes(AES_128_BLOCK_SIZE).collect();

        c10::aes_cbc_encrypt(&plaintext, &key, &iv)
    } else {
        c7::aes_ecb_encrypt(&plaintext, &key)
    }
}

pub enum AesMode {
    Cbc,
    Ecb,
}

pub fn aes_detection_oracle<F>(mut encrypter: F, block_size: usize) -> AesMode
    where F: FnMut(&[u8]) -> Vec<u8>
{
    // choose any plaintext such that the first two blocks are equal
    let chosen_plaintext = [0u8; u8::MAX as usize];
    let ciphertext = encrypter(&chosen_plaintext);
    let ciphertext_blocks: Vec<&[u8]> = ciphertext
        .chunks(block_size)
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

    let sum = (0..num_trials).fold(0, |acc, _| {
        acc + match aes_detection_oracle(|plaintext| aes_encryption_oracle(plaintext), AES_128_BLOCK_SIZE) {
            AesMode::Cbc => 0,
            AesMode::Ecb => 1
        }
    });

    let average = sum as f64 / num_trials as f64;
    println!("{}", average);

    assert!(0.5 - epsilon < average && average < 0.5 + epsilon);
}
