use crate::set1::{c1::Base64, c6, c7};
use std::collections::HashMap;
use std::convert::TryFrom;
use super::c11::{self, AesMode};

fn oracle(plaintext: &[u8]) -> Vec<u8> {
    const KEY: [u8; 16] = [239, 191, 189, 239, 191, 189, 69, 75, 239, 191, 189, 239, 191, 189, 239,
        191];
    let unknown_plaintext: Vec<u8> = {
        let s = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaG\
            UgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c\
            3QgZHJvdmUgYnkK";
    
        Base64::try_from(s).unwrap().to_bytes()
    };

    let full_plaintext = [plaintext, &unknown_plaintext].concat();
    c7::aes_ecb_encrypt(&full_plaintext, &KEY)
}

fn find_block_size() -> usize {
    let plaintext = vec![0u8; u8::MAX as usize]; 

    (1..u8::MAX)
        .map(|n| oracle(&plaintext[..n as usize]))
        .collect::<Vec<Vec<u8>>>()
        .windows(2)
        .enumerate()
        .take_while(|(i, ctxs)| ctxs[0][..*i+1] != ctxs[1][..*i+1])
        .count() + 1
}

fn decrypt_ciphertext() -> Vec<u8> {
    let block_size = find_block_size();
    let mut plaintext = Vec::new();

    for n in 0..oracle(&[]).len() {
        let almost_block = {
            if n < block_size - 1 {
                [vec![0u8; block_size - n - 1].as_slice(), plaintext.as_slice()].concat()
            } else {
                plaintext[n-(block_size-1)..].to_vec()
            }
        };

        let pad = vec![0; block_size - (n % block_size) - 1];

        let solved_nth_byte = {
            let block_number = n / block_size;
            let block_indexes = block_number*block_size..(block_number*block_size+block_size);
            let ciphertext = oracle(&pad);
            let ciphertext_block = &ciphertext[block_indexes];

            let maybe_solved_byte = (0..u8::MAX).find(|byte| {
                let mut block = almost_block.clone();
                block.push(*byte);

                ciphertext_block == &oracle(&block).to_vec()[..block_size]
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
    let block_size = find_block_size();
    assert_eq!(block_size, 16);

    if let AesMode::Cbc = c11::aes_detection_oracle(|p| oracle(p), block_size) {
        panic!();
    }

    let expected = "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on \
                    standby waving just to say hi\nDid you stop? No, I just drove by\n";
    assert_eq!(expected, String::from_utf8(decrypt_ciphertext()).unwrap());
}
