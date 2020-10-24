use crate::helpers;
use openssl::symm::{self, decrypt, encrypt, Cipher};

// Public
pub enum Mode {
    Cbc,
    //Ctr([u8; Aes::BLOCK_SIZE]),
    Ecb,
}

pub enum Aes {
    Cbc(CbcCrypter),
    //Ctr(CtrCrypter),
    Ecb(EcbCrypter),
}

impl Aes {
    pub const BLOCK_SIZE: usize = 16;

    pub fn new(key: [u8; Self::BLOCK_SIZE], mode: Mode) -> Self
    {
        match mode {
            Mode::Cbc => Self::Cbc(CbcCrypter::new(key)),
            //Mode::Ctr(iv) => CtrCrypter::new(iv, key),
            Mode::Ecb => Self::Ecb(EcbCrypter::new(key)),
        }
    }

    pub fn encrypt<T>(&mut self, plaintext: T, maybe_iv: Option<[u8; Self::BLOCK_SIZE]>)
        -> Result<Vec<u8>, &'static str>
        where T: AsRef<[u8]>
    {
        match self {
            Self::Cbc(crypter) => {
                maybe_iv
                    .ok_or("must specify an IV for CBC encryption!")
                    .map(|iv| crypter.encrypt(plaintext, iv))
            },
            //Ctr(crypter) => crypter.encrypt(plaintext),
            Self::Ecb(crypter) => Ok(crypter.encrypt(plaintext)),
        }
    }

    pub fn decrypt<T>(&mut self, ciphertext: T, maybe_iv: Option<[u8; Self::BLOCK_SIZE]>)
        -> Result<Vec<u8>, &'static str>
        where T: AsRef<[u8]>
    {
        match self {
            Self::Cbc(crypter) => {
                maybe_iv
                    .ok_or("must specify an IV for CBC decryption!")
                    .and_then(|iv| crypter.decrypt(ciphertext, iv))
            }
            //Ctr(crypter) => crypter.encrypt(plaintext),
            Self::Ecb(crypter) => Ok(crypter.decrypt(ciphertext)),
        }
    }
}

// Private
pub struct CbcCrypter {
    key: [u8; Aes::BLOCK_SIZE],
    openssl_encrypter: symm::Crypter,
    openssl_decrypter: symm::Crypter,
}

impl CbcCrypter {
    fn new(key: [u8; Aes::BLOCK_SIZE]) -> Self {
        let cipher = Cipher::aes_128_ecb();
        let mut openssl_encrypter = symm::Crypter::new(cipher, symm::Mode::Encrypt, &key, None)
            .unwrap();
        openssl_encrypter.pad(false);

        let mut openssl_decrypter = symm::Crypter::new(cipher, symm::Mode::Decrypt, &key, None)
            .unwrap();
        openssl_decrypter.pad(false);

        Self { key, openssl_encrypter, openssl_decrypter }
    }

    fn encrypt<T>(&mut self, plaintext: T, iv: [u8; Aes::BLOCK_SIZE]) -> Vec<u8>
        where T: AsRef<[u8]>
    {
        let mut encrypt_block = |block: &[u8]| -> Vec<u8> {
            let mut ciphertext = vec![0u8; Aes::BLOCK_SIZE * 2];
            self.openssl_encrypter.update(&block, &mut ciphertext).unwrap();
            self.openssl_encrypter.finalize(&mut ciphertext).unwrap();
            ciphertext.truncate(Aes::BLOCK_SIZE);

            ciphertext
        };

        // pkcs7 pad the plaintext
        let padded_plaintext = helpers::pkcs7_pad(plaintext.as_ref(), Aes::BLOCK_SIZE);

        // fold over the blocks of plaintext with the initialization vector as the first element of the
        // sequence of ciphertext blocks
        let ciphertext_blocks = padded_plaintext.chunks(Aes::BLOCK_SIZE)
            .fold(vec![iv.to_vec()], |mut acc, plaintext_block| {
                // XOR the current plaintext block with the previous ciphertext block
                let xored_plaintext = helpers::xor(acc.last().unwrap(), plaintext_block).unwrap();

                // encrypt the XORed plaintext block
                let ciphertext = encrypt_block(&xored_plaintext);

                acc.push(ciphertext);
                acc
            });

        ciphertext_blocks.iter().skip(1).flatten().copied().collect()
    }

    fn decrypt<T>(&mut self, ciphertext: T, iv: [u8; Aes::BLOCK_SIZE]) -> Result<Vec<u8>, &'static str>
        where T: AsRef<[u8]>
    {
        let mut decrypt_block = |block: &[u8]| -> Vec<u8> {
            let mut plaintext = vec![0u8; Aes::BLOCK_SIZE * 2];
            self.openssl_decrypter.update(block, &mut plaintext).unwrap();
            self.openssl_decrypter.finalize(&mut plaintext).unwrap();
            plaintext.truncate(Aes::BLOCK_SIZE);

            plaintext
        };

        let ciphertext_blocks: Vec<&[u8]> = vec![&iv[0..]]
            .iter()
            .copied()
            .chain(ciphertext.as_ref().chunks(Aes::BLOCK_SIZE))
            .collect();

        // fold over the ciphertext blocks. the first block in the sequence in the initialization
        // vector
        let plaintext = ciphertext_blocks.windows(2).fold(Vec::new(), |mut acc, ctxt_blocks| {
            // decrypt the ciphertext_block
            let xored_plaintext_block = decrypt_block(ctxt_blocks[1]);

            // XOR the decrypted ciphertext block with the previous ciphertext block to recover the
            // plaintext
            let mut plaintext_block = helpers::xor(&xored_plaintext_block, ctxt_blocks[0])
                .unwrap();

            acc.append(&mut plaintext_block);
            acc
        });

        helpers::pkcs7_unpad(&plaintext, Aes::BLOCK_SIZE).ok_or("invalid padding")
    }
}

//struct CtrCrypter {
    //iv: [u8; Aes::BLOCK_SIZE],
    //key: [u8; Aes::BLOCK_SIZE],
    //openssl_crypter: symm::Crypter,
//}

//impl CtrCrypter {
    //fn new(iv: [u8; Aes::BLOCK_SIZE], key: [u8; Aes::BLOCK_SIZE]) -> Self {

        ////Ok(Self { block_size, ecb_crypter, iv, key })
    //}
//}

pub struct EcbCrypter {
    key: [u8; Aes::BLOCK_SIZE],
    openssl_cipher: Cipher,
}

impl EcbCrypter {
    fn new(key: [u8; Aes::BLOCK_SIZE]) -> Self {
        let openssl_cipher = Cipher::aes_128_ecb();

        Self { key, openssl_cipher }
    }

    fn encrypt<T>(&self, plaintext: T) -> Vec<u8>
        where T: AsRef<[u8]>
    {
        encrypt(self.openssl_cipher, &self.key, None, plaintext.as_ref()).unwrap().clone()
    }

    fn decrypt<T>(&self, ciphertext: T) -> Vec<u8>
        where T: AsRef<[u8]>
    {
        decrypt(self.openssl_cipher, &self.key, None, ciphertext.as_ref()).unwrap().clone()
    }
}
