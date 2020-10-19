use crate::set1::{c1::Base64, c7};
use rand::{distributions::Uniform, Rng};
use std::convert::TryFrom;

struct Oracle {
    random_key: [u8; 16],
    random_prefix: Vec<u8>,
    unknown_plaintext: Vec<u8>,
}

impl Oracle {
    const BLOCK_SIZE: usize = 16;

    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let range = Uniform::new(0, u8::MAX);

        let random_prefix: Vec<u8> = {
            let random_count = rng.sample(&range);

            (0..random_count).map(|_| rng.sample(&range)).collect()
        };

        let mut random_key = [0u8; 16];
        for i in 0..Self::BLOCK_SIZE { random_key[i] = rng.sample(&range) }

        let unknown_plaintext = {
            let s = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdw\
                pUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vL\
                CBJIGp1c3QgZHJvdmUgYnkK";
        
            Base64::try_from(s).unwrap().to_bytes()
        };

        Oracle { random_key, random_prefix, unknown_plaintext }
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let full_plaintext = [&self.random_prefix, plaintext, &self.unknown_plaintext].concat();

        c7::aes_ecb_encrypt(&full_plaintext, &self.random_key)
    }
}

fn decrypt_ciphertext() -> Vec<u8> {
    let oracle = Oracle::new();

    let number_of_full_prefix_blocks = {
        let without_chosen_plaintext = oracle.encrypt(&[]);
        let with_chosen_plaintext = oracle.encrypt(&[0]);
        let zipper = without_chosen_plaintext.chunks(Oracle::BLOCK_SIZE)
            .zip(with_chosen_plaintext.chunks(Oracle::BLOCK_SIZE));

        zipper
            .take_while(|(c1, c2)| c1 == c2)
            .count()
    };

    let distance_from_block_boundary = {
        let ciphertexts = (0..Oracle::BLOCK_SIZE+1)
            .map(|n| oracle.encrypt(&vec![0u8; n]))
            .collect::<Vec<Vec<u8>>>();
        
        let start = number_of_full_prefix_blocks * Oracle::BLOCK_SIZE;
        let end = start + Oracle::BLOCK_SIZE;
        ciphertexts.windows(2).take_while(|cs| cs[0][start..end] != cs[1][start..end]).count()
    };

    let mut plaintext = Vec::new();

    for n in 0..oracle.encrypt(&[]).len() {
        let solved_nth_byte = {
            // pass pad bytes to the oracle such that the byte we are solving for is the final byte
            // in a block; given that we know the previous Oracle::BLOCK_SIZE-1 bytes of plaintext,
            // we are able to brute force this plaintext byte
            let pad = {
                let pad_length = Oracle::BLOCK_SIZE - (n % Oracle::BLOCK_SIZE) - 1 +
                    distance_from_block_boundary;

                vec![0; pad_length]
            };

            let ciphertext = oracle.encrypt(&pad);

            // isolate the block of ciphertext we are interested in
            let block_number = n / Oracle::BLOCK_SIZE + number_of_full_prefix_blocks + 1 +
                (distance_from_block_boundary as f64 / Oracle::BLOCK_SIZE as f64).ceil() as usize;

            // choose our plaintext to be the pad we use to align the unknown byte to a block
            // boundary concatenated to the plaintext we know so far
            let chosen_plaintext = [&pad, plaintext.as_slice()].concat();

            // compare the ciphertext prefix to all of the possible ones to brute force this byte
            let maybe_solved_byte = (0..u8::MAX).find(|byte| {
                let mut p = chosen_plaintext.clone();
                p.push(*byte);
                let candidate = &oracle.encrypt(&p).to_vec()[..block_number*Oracle::BLOCK_SIZE];

                &ciphertext[..block_number*Oracle::BLOCK_SIZE] == candidate
            });

            match maybe_solved_byte {
                Some(solved_byte) => solved_byte,
                None => {
                    // this situation implies that the previous solved byte in the plaintext is now
                    // different than it was in the last loop iteration, which means it was a pad
                    // byte. remove it and finish
                    plaintext.pop();
                    break;
                }
            }
        };

        plaintext.push(solved_nth_byte);
    }

    plaintext
}

#[test]
fn verify() {
    for _ in 0..100 {
    let expected = "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on \
                    standby waving just to say hi\nDid you stop? No, I just drove by\n";
    assert_eq!(expected, String::from_utf8(decrypt_ciphertext()).unwrap());
    }
}
