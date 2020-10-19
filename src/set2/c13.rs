use crate::set1::c7;
use super::c12;
use std::collections::HashMap;

fn parse_kv(kv_string: &str) -> HashMap<String, String> {
    let mut dict = HashMap::new();

    for pair_iter in kv_string.split('&').map(|pair| pair.splitn(2, '=')) {
        let pair: Vec<String> = pair_iter.map(String::from).collect();

        if pair.len() == 2 {
            dict.insert(pair[0].clone(), pair[1].clone());
        }
    }

    dict
}

fn profile_for(email: &str) -> String {
    let escaped_email = email.replace('&', "\\&").replace('=', "\\=");

    format!("email={}&uid=10&role=user", escaped_email)
}

const KEY: [u8; 16] = [59, 44, 55, 239, 191, 189, 106, 239, 191, 189, 217, 156, 239, 191, 189, 239];

fn encrypt_profile(profile: &str) -> Vec<u8> {
    c7::aes_ecb_encrypt(profile.as_bytes(), &KEY)
}

fn decrypt_profile(ciphertext: &[u8]) -> String {
    String::from_utf8(c7::aes_ecb_decrypt(ciphertext, &KEY)).unwrap()
}

fn oracle(email: &str) -> Vec<u8> {
    encrypt_profile(&profile_for(email))
}

fn create_admin_role() -> Vec<u8> {
    // APPROACH
    //
    // we need to choose input such that the final block is just user so we can replace it with the
    // ciphertext produced by "admin" alone (with the proper pad bytes)
    //
    // this approach requires a predictable uid - its length has an effect on how many pad bytes
    // we need to add to our chosen plaintexts
    //
    let block_size = 16;
    let admin_ciphertext_block = {
        let num_pad_bytes =  block_size - "admin".len();
        let num_lead_bytes = block_size - "email=".len();
        let admin_plaintext_block = [
                // add leading bytes so "admin" begins at a block boundary
                vec![0u8; num_lead_bytes].as_slice(),
                "admin".as_bytes(),
                // add padding bytes to mimic the pkcs#7 padding done by AES
                vec![num_pad_bytes as u8; num_pad_bytes].as_slice()
            ].concat();
        let c = oracle(&String::from_utf8(admin_plaintext_block).unwrap());

        // isolate the ciphertext block that corresponds to the "admin" plaintext block created
        // above
        c[block_size..block_size*2].to_vec()
    };

    // choose an email address that pushes the role name ("user") to begin a new block (the last
    // one)
    let email = "a@website.com";
    let mut ciphertext = oracle(email);

    // replace the final ciphertext block with the one we created above
    let offset = 2 * block_size;
    for i in 0..block_size {
        ciphertext[offset + i] = admin_ciphertext_block[i];
    }

    ciphertext
}

#[test]
fn verify() {
    let admin_role = decrypt_profile(&create_admin_role());
    let profile = parse_kv(&admin_role);
    let role = profile.get("role").unwrap();
    assert_eq!(role, "admin");
}
