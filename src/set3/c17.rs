use crate::block_ciphers::{Aes, Input, Mode};
use crate::helpers::{self, Base64};
use crate::set2::{c9, c10};
use rand::{distributions::Uniform, Rng};
use std::collections::HashSet;
use std::convert::TryFrom;

struct Oracle {
    aes: Aes,
    iv: [u8; Aes::BLOCK_SIZE],
    plaintexts: Vec<Vec<u8>>,
}

impl Oracle {
    const PLAINTEXTS: [&'static str; 10] = [
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ];

    fn new() -> Self {
        let mut key = [0u8; Aes::BLOCK_SIZE];
        for i in 0..Aes::BLOCK_SIZE { key[i] = rand::random::<u8>() }

        let mut iv = [0u8; Aes::BLOCK_SIZE];
        for i in 0..Aes::BLOCK_SIZE { iv[i] = rand::random::<u8>() }


        let aes = Aes::new(key, Mode::Cbc);

        let plaintexts = Self::PLAINTEXTS.iter()
            .map(|plaintext| Base64::try_from(*plaintext).unwrap().to_bytes())
            .collect();

        Oracle { aes, iv, plaintexts }
    }

    fn encrypt(&mut self) -> Vec<u8> {
        let plaintext = {
            let mut rng = rand::thread_rng();
            let dist = Uniform::new(0, Self::PLAINTEXTS.len());
            &self.plaintexts[rng.sample(&dist)]
        };

        [&self.iv[..], &self.aes.encrypt(plaintext, Input::Iv(self.iv)).unwrap()].concat()
    }

    fn decrypt(&mut self, ciphertext: &[u8], iv: [u8; Aes::BLOCK_SIZE]) -> bool {
        self.aes.decrypt(ciphertext, Input::Iv(iv)).is_ok()
    }
}

// APPROACH
//
// 1. starting with IV, randomly choose a ciphertext block and concat with following ctext block
// 2. keep trying ctext blocks until decrypt() returns true, at which point we know the last
//    byte of the plaintext (\x01)
// 3. recover the last original plaintext byte via random_iv[len-1] ^ \x01 ^ last byte of 
//    original IV
// 4. fix the last byte of the random IV to be orignal plaintext last byte XOR \x02 and 
//    randomly choose IVs until padding is valid
// 5. we know the second to last byte of the plaintext is very likely \x02
// 6. recover actual second to last plaintext byte via random_iv[len-2] ^ \x02 ^ second to last
//    byte of original IV
// 7. fix the last two bytes of the random IV to be the original two plaintext last bytes XORed
//    with \x03
// 8. generalize
fn attack() -> Vec<Vec<u8>> {
    let mut oracle = Oracle::new();
    let ciphertexts = {
        let mut set = HashSet::new();

        while set.len() < 10 {
            set.insert(oracle.encrypt());
        }

        set.iter().cloned().collect::<Vec<Vec<u8>>>()
    };

    fn randomize(block: &mut [u8; Aes::BLOCK_SIZE], suffix_length: usize) -> Option<()> {
        if suffix_length < Aes::BLOCK_SIZE {
            let prefix_length = Aes::BLOCK_SIZE - suffix_length;

            for n in 0..prefix_length { block[n] = rand::random::<u8>() }

            Some(())
        } else {
            None
        }
    }

    let mut solve_block = |prev_block: &[u8], block: &[u8]| -> Vec<u8> {
        let mut chosen_ciphertext = [0u8; Aes::BLOCK_SIZE];
        let mut plaintext_block = Vec::new();

        for n in 0..Aes::BLOCK_SIZE {
            // fix the last n bytes of the chosen ciphertext block to be the expected pad byte
            // (n + 1) XORed with the corresponding byte in the plaintext (known at this point)
            // XORed with the corresponding byte in the previous ciphertext block. this yields
            // a byte which, when XORed with the corresponding chosen ciphertext block, yields the
            // desired pad byte. this step "fixes" bytes in the plaintext to be our expected pad
            // bytes, so we can brute force the byte required in the previous ciphertext block to
            // yield the leftmost pad byte.
            for (i, byte) in plaintext_block.iter().rev().enumerate() {
                let index = (Aes::BLOCK_SIZE - n) + i;
                chosen_ciphertext[index] = byte ^ prev_block[index] ^ (n + 1) as u8
            }

            loop {
                // choose a random ciphertext block, keeping the last n bytes fixed
                randomize(&mut chosen_ciphertext, n).unwrap();

                // ask the oracle if the current ciphertext block yields plaintext with valid
                // padding given our chosen ciphertext as the IV
                if oracle.decrypt(&block, chosen_ciphertext) { 
                    // the oracle told us that the padding is valid, so we know that the byte in 
                    // the block_size - n spot is our expcted pad byte (n + 1). with this info, we
                    // can recover the orignal byte in the plaintext by XORing the block_size - n
                    // byte in the chosen ciphertext (the IV in this case), the pad byte (n + 1),
                    // and the block_size - n byte in the previous ciphertext block.
                    let index = Aes::BLOCK_SIZE - n - 1;
                    let original_byte = chosen_ciphertext[index] ^ ((n + 1) as u8) ^ prev_block[index];
                    plaintext_block.push(original_byte);

                    break;
                }
            }
        }

        plaintext_block.reverse();
        plaintext_block
    };

    ciphertexts.iter().map(|ciphertext| {
        let padded_plaintext = ciphertext
            .chunks(Aes::BLOCK_SIZE)
            .collect::<Vec<&[u8]>>()
            .windows(2)
            .map(|blocks| solve_block(blocks[0], blocks[1]))
            .flatten()
            .collect::<Vec<u8>>();

        helpers::pkcs7_unpad(&padded_plaintext, Aes::BLOCK_SIZE).unwrap()
    }).collect::<Vec<Vec<u8>>>()
}

#[test]
fn verify() {
    let mut plaintexts = attack().iter()
        .map(|p| String::from_utf8(p.clone()).unwrap())
        .collect::<Vec<String>>();
    plaintexts.sort();

    let expected_plaintext = "000000Now that the party is jumping\n000001With the bass kicked in \
                              and the Vega\'s are pumpin\'\n000002Quick to the point, to the \
                              point, no faking\n000003Cooking MC\'s like a pound of \
                              bacon\n000004Burning \'em, if you ain\'t quick and nimble\n000005I \
                              go crazy when I hear a cymbal\n000006And a high hat with a souped up \
                              tempo\n000007I\'m on a roll, it\'s time to go solo\n000008ollin\' in \
                              my five point oh\n000009ith my rag-top down so my hair can blow";
    assert_eq!(expected_plaintext, plaintexts.join("\n"));
}

