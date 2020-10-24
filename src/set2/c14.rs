use crate::helpers::Base64;
use crate::block_ciphers::{Aes, Mode};
use std::convert::TryFrom;

struct Oracle {
    aes: Aes,
    prefix: Vec<u8>,
    suffix: Vec<u8>,
}

impl Oracle {
    const UNKNOWN_PLAINTEXT: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc2\
        8gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQge\
        W91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    fn new() -> Self {
        let prefix: Vec<u8> = {
            let random_count = rand::random::<u8>();

            (0..random_count).map(|_| rand::random::<u8>()).collect()
        };

        let mut key = [0u8; 16];
        for i in 0..Aes::BLOCK_SIZE { key[i] = rand::random::<u8>() }

        let suffix = Base64::try_from(Self::UNKNOWN_PLAINTEXT).unwrap().to_bytes();

        let aes = Aes::new(key, Mode::Ecb);

        Oracle { aes, prefix, suffix }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let full_plaintext = [&self.prefix, plaintext, &self.suffix].concat();

        self.aes.encrypt(&full_plaintext, None).unwrap()
    }
}

fn decrypt_ciphertext() -> Vec<u8> {
    let mut oracle = Oracle::new();

    let number_of_full_prefix_blocks = {
        let without_chosen_plaintext = oracle.encrypt(&[]);
        let with_chosen_plaintext = oracle.encrypt(&[0]);
        let zipper = without_chosen_plaintext.chunks(Aes::BLOCK_SIZE)
            .zip(with_chosen_plaintext.chunks(Aes::BLOCK_SIZE));

        zipper
            .take_while(|(c1, c2)| c1 == c2)
            .count()
    };

    let distance_from_block_boundary = {
        let ciphertexts = (0..Aes::BLOCK_SIZE+1)
            .map(|n| oracle.encrypt(&vec![0u8; n]))
            .collect::<Vec<Vec<u8>>>();
        
        let start = number_of_full_prefix_blocks * Aes::BLOCK_SIZE;
        let end = start + Aes::BLOCK_SIZE;
        ciphertexts.windows(2).take_while(|cs| cs[0][start..end] != cs[1][start..end]).count()
    };

    let mut plaintext = Vec::new();

    for n in 0..oracle.encrypt(&[]).len() {
        let solved_nth_byte = {
            // pass pad bytes to the oracle such that the byte we are solving for is the final byte
            // in a block; given that we know the previous Aes::BLOCK_SIZE-1 bytes of plaintext,
            // we are able to brute force this plaintext byte
            let pad = {
                let pad_length = Aes::BLOCK_SIZE - (n % Aes::BLOCK_SIZE) - 1 +
                    distance_from_block_boundary;

                vec![0; pad_length]
            };

            let ciphertext = oracle.encrypt(&pad);

            // isolate the block of ciphertext we are interested in
            let block_number = n / Aes::BLOCK_SIZE + number_of_full_prefix_blocks + 1 +
                (distance_from_block_boundary as f64 / Aes::BLOCK_SIZE as f64).ceil() as usize;

            // choose our plaintext to be the pad we use to align the unknown byte to a block
            // boundary concatenated to the plaintext we know so far
            let chosen_plaintext = [&pad, plaintext.as_slice()].concat();

            // compare the ciphertext prefix to all of the possible ones to brute force this byte
            let maybe_solved_byte = (0..u8::MAX).find(|byte| {
                let mut p = chosen_plaintext.clone();
                p.push(*byte);
                let candidate = &oracle.encrypt(&p).to_vec()[..block_number*Aes::BLOCK_SIZE];

                &ciphertext[..block_number*Aes::BLOCK_SIZE] == candidate
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
        let expected = "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies \
                        on standby waving just to say hi\nDid you stop? No, I just drove by\n";
        assert_eq!(expected, String::from_utf8(decrypt_ciphertext()).unwrap());
    }
}
