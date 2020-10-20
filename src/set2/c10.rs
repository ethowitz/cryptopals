use crate::set1::{c1::Base64, c2, c7};
use openssl::symm::{Cipher, Crypter, Mode};
use rand::{distributions::Uniform, Rng};
use std::{convert::TryFrom, fs};
use super::c9;

const AES_128_BLOCK_SIZE: usize = 16;

struct AesEncrypter {
    encrypter: Crypter,
}

impl AesEncrypter {
    fn new(key: &[u8]) -> Self {
        let cipher = Cipher::aes_128_ecb();

        let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, None).unwrap();
        encrypter.pad(false);

        AesEncrypter { encrypter }
    }

    pub fn encrypt_block(&mut self, block: &[u8]) -> Option<Vec<u8>> {
        if block.len() == AES_128_BLOCK_SIZE {
            let mut ciphertext = vec![0u8; AES_128_BLOCK_SIZE * 2];
            self.encrypter.update(block, &mut ciphertext).unwrap();
            self.encrypter.finalize(&mut ciphertext).unwrap();
            ciphertext.truncate(AES_128_BLOCK_SIZE);

            Some(ciphertext)
        } else {
            None
        }
    }
}

struct AesDecrypter {
    decrypter: Crypter,
}

impl AesDecrypter {
    fn new(key: &[u8]) -> Self {
        let cipher = Cipher::aes_128_ecb();

        let mut decrypter = Crypter::new(cipher, Mode::Decrypt, key, None).unwrap();
        decrypter.pad(false);

        AesDecrypter { decrypter }
    }

    pub fn decrypt_block(&mut self, block: &[u8]) -> Option<Vec<u8>> {
        if block.len() == AES_128_BLOCK_SIZE {
            let mut plaintext = vec![0u8; AES_128_BLOCK_SIZE * 2];
            self.decrypter.update(block, &mut plaintext).unwrap();
            self.decrypter.finalize(&mut plaintext).unwrap();
            plaintext.truncate(AES_128_BLOCK_SIZE);

            Some(plaintext)
        } else {
            None
        }
    }
}

pub fn aes_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encrypter = AesEncrypter::new(key);

    // pkcs7 pad the plaintext
    let padded_plaintext = c9::pkcs7_pad(plaintext, AES_128_BLOCK_SIZE as u8);

    // fold over the blocks of plaintext with the initialization vector as the first element of the
    // sequence of ciphertext blocks
    let ciphertext_blocks = padded_plaintext.chunks(AES_128_BLOCK_SIZE)
        .fold(vec![iv.to_vec()], |mut acc, plaintext_block| {
            // XOR the current plaintext block with the previous ciphertext block
            let xored_plaintext = c2::xor(acc.last().unwrap(), plaintext_block).unwrap();

            // encrypt the XORed plaintext block
            let ciphertext = encrypter.encrypt_block(&xored_plaintext).unwrap();

            acc.push(ciphertext);
            acc
        });

    ciphertext_blocks.iter().skip(1).flatten().copied().collect()
}

pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Option<Vec<u8>> {
    if ciphertext.len() % AES_128_BLOCK_SIZE == 0 && iv.len() == AES_128_BLOCK_SIZE {
        let mut decrypter = AesDecrypter::new(key);
        let ciphertext_blocks: Vec<&[u8]> = vec![iv]
            .iter()
            .copied()
            .chain(ciphertext.chunks(AES_128_BLOCK_SIZE))
            .collect();

        // fold over the ciphertext blocks. the first block in the sequence in the initialization
        // vector
        let plaintext = ciphertext_blocks.windows(2).fold(Vec::new(), |mut acc, ctxt_blocks| {
            // decrypt the ciphertext_block
            let xored_plaintext_block = decrypter.decrypt_block(ctxt_blocks[1]).unwrap();

            // XOR the decrypted ciphertext block with the previous ciphertext block to recover the
            // plaintext
            let mut plaintext_block = c2::xor(&xored_plaintext_block, ctxt_blocks[0])
                .unwrap();

            acc.append(&mut plaintext_block);
            acc
        });

        Some(c9::pkcs7_unpad(&plaintext, AES_128_BLOCK_SIZE as u8).unwrap())
    } else {
        None
    }
}

#[test]
fn verify() {
    let raw = fs::read_to_string("./src/set2/10.txt").unwrap();
    let base64 = Base64::try_from(raw.replace("\n", "").as_str()).unwrap();
    let ciphertext = base64.to_bytes();
    println!("{:?}", ciphertext);
    let iv = vec![0u8; AES_128_BLOCK_SIZE];
    let plaintext = aes_cbc_decrypt(&ciphertext, b"YELLOW SUBMARINE", &iv).unwrap();
    let expected_plaintext = b"I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while \
                              the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my \
                              DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies \
                              goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m \
                              lettin\' my drug kick in \nIt controls my mouth and I begin \nTo \
                              just let it flow, let my concepts go \nMy posse\'s to the side \
                              yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will \
                              be \nAnd if you don\'t give a damn, then \nWhy you starin\' at \
                              me \nSo get off \'cause I control the stage \nThere\'s no dissin\' \
                              allowed \nI\'m in my own phase \nThe girlies sa y they love me and \
                              that is ok \nAnd I can dance better than any kid n\' play \n\n\
                              Stage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so \
                              let the beat play through \nSo I can funk it up and make it sound \
                              good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my \
                              rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an \
                              effect and that you can bet \nI can take a fly girl and make her \
                              wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no \
                              denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my \
                              style \nOver and over, practice makes perfect \nBut not if you\'re a \
                              loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon \
                              -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! \
                              Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard \
                              like a rhino \nIntoxicating so you stagger like a wino \nSo punks \
                              stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you \
                              people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy \
                              Glue \nMovin\' and groovin\' trying to sing along \nAll through the \
                              ghetto groovin\' this here song \nNow you\'re amazed by the VIP \
                              posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the \
                              bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just \
                              gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \
                              \nYou trapped me once and I thought that \nYou might have it \nSo \
                              step down and lend me your ear \n\'89 in my time! You, \'90 is my \
                              year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour \
                              body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and \
                              don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me \
                              Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the \
                              witch doctor, Ice, do the dance to cure \nSo come up close and \
                              don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou \
                              thought that I was weak, Boy, you\'re dead wrong \nSo come on, \
                              everybody and sing this song \n\nSay -- Play that funky music Say, \
                              go white boy, go white boy go \nplay that funky music Go white boy, \
                              go white boy, go \nLay down and boogie and play that funky music \
                              till you die. \n\nPlay that funky music Come on, Come on, let me \
                              hear \nPlay that funky music white boy you say it, say it \nPlay \
                              that funky music A little louder now \nPlay that funky music, white \
                              boy Come on, Come on, Come on \nPlay that funky music \n";

    assert_eq!(expected_plaintext, plaintext.as_slice());
}
