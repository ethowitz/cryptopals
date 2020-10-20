use rand::{distributions::Uniform, Rng};
use super::{c10, c15};

struct Oracle {
    key: Vec<u8>,
}

impl Oracle {
    const ADMIN_ROLE_IDENTIFIER: &'static str = ";admin=true;";
    const BLOCK_SIZE: usize = 16;
    const IV: [u8; Self::BLOCK_SIZE] = [0u8; Self::BLOCK_SIZE];
    const PREFIX: &'static [u8] = b"comment1=cooking%20MCs;userdata=";
    const SUFFIX: &'static [u8] = b";comment2=%20like%20a%20pound%20of%20bacon";

    fn new() -> Self {
        let mut rng = rand::thread_rng();
        let dist = Uniform::new(0, u8::MAX);
        let key = (0..Self::BLOCK_SIZE).map(|_| rng.sample(&dist)).collect();
        
        Oracle { key }
    }

    fn encrypt(&self, plaintext: &str) -> Vec<u8> {
        let escaped_plaintext = plaintext.replace(';', "\\;").replace('=', "\\=");
        let full_plaintext = [Self::PREFIX, escaped_plaintext.as_bytes(), Self::SUFFIX].concat();

        c10::aes_cbc_encrypt(&full_plaintext, &self.key, &Self::IV)
    }

    fn is_admin(&self, ciphertext: &[u8]) -> bool {
        let plaintext = c10::aes_cbc_decrypt(ciphertext, &self.key, &Self::IV).unwrap();
        let data = String::from_utf8_lossy(&plaintext);

        data.contains(Self::ADMIN_ROLE_IDENTIFIER)
    }
}

fn generate_admin_ciphertext(oracle: &Oracle) -> Vec<u8> {
    // compute the number of full blocks of the unknown prefix
    let number_of_full_prefix_blocks = {
        let without_chosen_plaintext = oracle.encrypt("");
        let with_chosen_plaintext = oracle.encrypt("0");
        let zipper = without_chosen_plaintext.chunks(Oracle::BLOCK_SIZE)
            .zip(with_chosen_plaintext.chunks(Oracle::BLOCK_SIZE));

        zipper.take_while(|(c1, c2)| c1 == c2).count()
    };

    // compute the "remainder" (the number of bytes remaining in the last (partial) block of the
    // prefix)
    let distance_from_block_boundary = {
        let ciphertexts = (0..Oracle::BLOCK_SIZE+1)
            .map(|n| oracle.encrypt(&String::from_utf8(vec![0u8; n]).unwrap()))
            .collect::<Vec<Vec<u8>>>();
        
        let start = number_of_full_prefix_blocks * Oracle::BLOCK_SIZE;
        let end = start + Oracle::BLOCK_SIZE;
        ciphertexts.windows(2).take_while(|cs| cs[0][start..end] != cs[1][start..end]).count()
    };

    // choose a plaintext consisting of all zeroes to simplify the edits we need to perform on the
    // ciphertext
    let chosen_plaintext = vec![0u8; distance_from_block_boundary + Oracle::BLOCK_SIZE * 2];
    let mut ciphertext = oracle.encrypt(&String::from_utf8(chosen_plaintext).unwrap());

    let role = Oracle::ADMIN_ROLE_IDENTIFIER.as_bytes();
    let offset = number_of_full_prefix_blocks * Oracle::BLOCK_SIZE + distance_from_block_boundary +
        (Oracle::BLOCK_SIZE - role.len());

    // assume we are trying to make edits to the ciphertext such that plaintext block j (p_j)
    // contains the string ";admin=true;". c_j-1 is the ciphertext block that comes before the
    // ciphertext block corresponding to our target plaintext block. c'_j-1 is the edited
    // ciphertext block. let X represent the edited plaintext block. we need to choose c'_j-1
    // such that c'_j-1 XOR E^-1(c_j) = X. so:
    //
    // c'_j-1 XOR E^-1(c_j) = X
    // c'_j-1 = X XOR E^-1(c_j) (since A XOR A = 0 and A XOR 0 = A for arbitrary A)
    // c'_j-1 = X XOR c_j-1 XOR p_j (by definition of decryption in the CBC block cipher mode)
    // c'_j-1 = X XOR c_j-1 (since we chose p_j to be 0, and A XOR 0 = A for arbitrary A) 
    //
    // so, we need to choose c'_j-1 to be our desired plaintext XORed with the ciphertext block
    // c_j-1
    for i in 0..role.len() { ciphertext[offset+i] ^= role[i] }

    ciphertext
}

#[test]
fn verify() {
    let oracle = Oracle::new();
    let admin_ciphertext = generate_admin_ciphertext(&oracle);
    assert!(oracle.is_admin(&admin_ciphertext));
}
