use std::cmp::Ordering;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{self, BufRead};
use super::challenge1::Hex;
use super::challenge6;

fn detect_aes_ecb(buffers: &[&[u8]]) -> Option<Vec<u8>> {
    const AES_BLOCK_SIZE: usize = 16;

    let get_average_hamming_distance = |buffer: &[u8]| {
        let number_of_blocks = buffer.len() / AES_BLOCK_SIZE;
        let hamming_distances = (0..(number_of_blocks-1)).flat_map(|i: usize| -> Vec<usize> {
            (i..(number_of_blocks-1)).map(|j| {
                challenge6::get_hamming_distance(&buffer[i*AES_BLOCK_SIZE..(i+1)*AES_BLOCK_SIZE],
                    &buffer[j*AES_BLOCK_SIZE..(j+1)*AES_BLOCK_SIZE]).unwrap()
            }).collect()
        });
        
        hamming_distances.sum::<usize>() as f64 / number_of_blocks as f64
    };

    buffers.iter().min_by(|buffer1, buffer2| {
        let average_hamming_distance1 = get_average_hamming_distance(buffer1);
        let average_hamming_distance2 = get_average_hamming_distance(buffer2);

        average_hamming_distance1
            .partial_cmp(&average_hamming_distance2)
            .unwrap_or(Ordering::Equal)
    }).map(|buffer| buffer.to_vec())
}

#[test]
fn verify() {
    let file = File::open("./src/set1/8.txt").unwrap();
    let lines = io::BufReader::new(file).lines().filter_map(Result::ok);
    let ciphertexts: Vec<Vec<u8>> = lines
        .map(|hex| Hex::try_from(hex.as_str()).unwrap().to_bytes())
        .collect();
    let vec_of_slices: Vec<&[u8]> = ciphertexts.iter().map(|buffer| buffer.as_slice()).collect();
    let ciphertext = detect_aes_ecb(&vec_of_slices).unwrap();
    let hex = Hex::from_bytes(&ciphertext);

    let expected_hex = "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b6\
                        41dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d\
                        9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b030\
                        8649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2\
                        c123c58386b06fba186a";
    assert_eq!(expected_hex, hex.to_string());
}
