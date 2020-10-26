use crate::block_ciphers::{Aes, Input, Mode};
use crate::helpers::Base64;
use std::collections::HashMap;
use std::convert::TryFrom;
use super::c11::{self, AesMode};

struct Oracle {
    aes: Aes,
    suffix: Vec<u8>,
}

impl Oracle {
    const UNKNOWN_PLAINTEXT: &'static str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc2\
        8gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQge\
        W91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    fn new() -> Self {
        let mut key = [0u8; Aes::BLOCK_SIZE];
        for i in 0..Aes::BLOCK_SIZE { key[i] = rand::random::<u8>() }

        let aes = Aes::new(key, Mode::Ecb);
        let suffix = Base64::try_from(Self::UNKNOWN_PLAINTEXT).unwrap().to_bytes();

        Self { aes, suffix }
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        self.aes.encrypt([plaintext, &self.suffix].concat(), Input::Nothing).unwrap()
    }
}

pub fn find_block_size<F>(mut encrypter: F) -> usize
    where F: FnMut(&[u8]) -> Vec<u8>
{
    let plaintext = vec![0u8; u8::MAX as usize]; 

    // compute ciphertexts using plaintexts \x0, \x0\x0, \x0\x0\x0, etc. the index of the first
    // ciphertext in the list whose first block matches that of the subsequent ciphertext in the
    // list is our block size. this exploits the property that the same block of plaintext
    // encrypted with the same key always produces the same block of ciphertext: we know we've
    // found a block boundary once our plaintext has grown to a size such that the first block of
    // ciphertext is unchanged with an additional byte of plaintext.
    (1..u8::MAX)
        .map(|n| encrypter(&plaintext[..n as usize]))
        .collect::<Vec<Vec<u8>>>()
        .windows(2)
        .enumerate()
        .take_while(|(i, ctxs)| ctxs[0][..*i+1] != ctxs[1][..*i+1])
        .count() + 1
}

// INTUITION
//
// given a function that prepends known plaintext to unknown plaintext prior to encryption, we can
// exploit the property of the ECB mode that a given block of plaintext always produces the same
// block of ciphertext. since we can an provide arbitrary known-plaintext prefix to the oracle,
// we can ensure that we /always/ know the 15 bytes of plaintext prior to the byte we are trying to
// solve. this allows us to brute force each byte of plaintext by pushing the byte we are solving
// for to be the last byte of a block and comparing the resulting ciphertext block to the 2^8
// possible ciphertext blocks.
fn decrypt_ciphertext() -> Vec<u8> {
    let mut oracle = Oracle::new();
    let block_size = find_block_size(|p| oracle.encrypt(p));
    let mut plaintext = Vec::new();

    for n in 0..oracle.encrypt(&[]).len() {

        let solved_nth_byte = {
            // pass pad bytes to the oracle such that the byte we are solving for is the final byte
            // in a block; given that we know the previous block_size-1 bytes of plaintext, we are
            // able to brute force this plaintext byte.
            let pad = vec![0; block_size - (n % block_size) - 1];
            let ciphertext = oracle.encrypt(&pad);

            // isolate the block of ciphertext we are interested in
            let block_number = n / block_size;
            let block_indexes = block_number*block_size..(block_number*block_size+block_size);
            let ciphertext_block = &ciphertext[block_indexes];

            // choose the previous `block_size-1` plaintext bytes to use during our brute force
            // attack. if we don't have `block_size-1` plaintext bytes, pad the rest with zeroes
            let almost_block = {
                if n < block_size - 1 {
                    [vec![0u8; block_size - n - 1].as_slice(), plaintext.as_slice()].concat()
                } else {
                    plaintext[n-(block_size-1)..].to_vec()
                }
            };

            // compare the isolated ciphertext block to all of the possible ones to brute force
            // this byte
            let maybe_solved_byte = (0..u8::MAX).find(|byte| {
                let mut block = almost_block.clone();
                block.push(*byte);

                ciphertext_block == &oracle.encrypt(&block).to_vec()[..block_size]
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
    let mut oracle = Oracle::new();
    let block_size = find_block_size(|p| oracle.encrypt(p));
    assert_eq!(block_size, 16);

    if let AesMode::Cbc = c11::aes_detection_oracle(|p| oracle.encrypt(p)) {
        panic!();
    }

    let expected = "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on \
                    standby waving just to say hi\nDid you stop? No, I just drove by\n";
    assert_eq!(expected, String::from_utf8(decrypt_ciphertext()).unwrap());
}
