use crate::set1::c7;
use rand::{distributions::Uniform, Rng};
use super::c10;

const AES_128_BLOCK_SIZE: usize = 16;

pub fn aes_encryption_oracle(buffer: &[u8]) -> Vec<u8> {
    let gen_bytes = |n| {
        let byte_range = Uniform::new(0, u8::MAX);
        let mut rng = rand::thread_rng();

        (0..n).map(move |_| rng.sample(&byte_range))
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
        let iv: Vec<u8> = {
            let mut rng = rand::thread_rng();
            let range = Uniform::new(0, u8::MAX);

            (0..AES_128_BLOCK_SIZE).map(|_| rng.sample(&range)).collect()
        };

        c10::aes_cbc_encrypt(&plaintext, &key, &iv)
    } else {
        c7::aes_ecb_encrypt(&plaintext, &key)
    }
}

enum AesMode {
    Cbc,
    Ecb,
}

fn aes_detection_oracle() -> AesMode {
    let chosen_plaintext = [0u8; 43];
    let ciphertext = aes_encryption_oracle(&chosen_plaintext);
    let ciphertext_blocks: Vec<&[u8]> = ciphertext
        .chunks(AES_128_BLOCK_SIZE)
        .collect();

    if ciphertext_blocks[1] == ciphertext_blocks[2] {
        AesMode::Ecb
    } else {
        AesMode::Cbc
    }
}

#[test]
fn verify() {
    let epsilon = 0.05;
    let num_trials = 10000;

    let sum = (0..num_trials).fold(0, |acc, _| {
        acc + match aes_detection_oracle() {
            AesMode::Cbc => 0,
            AesMode::Ecb => 1
        }
    });

    let average = sum as f64 / num_trials as f64;
    println!("{}", average);

    assert!(0.5 - epsilon < average && average < 0.5 + epsilon);
}
