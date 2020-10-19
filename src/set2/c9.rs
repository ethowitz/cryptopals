pub fn pkcs7_pad(buffer: &[u8], block_size: u8) -> Vec<u8> {
    let pad_start: u8 = (buffer.len() % block_size as usize) as u8;
    let pad: u8 = if pad_start == 0 {
        block_size
    } else {
        block_size - pad_start
    };

    let mut padded = buffer.to_vec();

    for _ in 0..pad { padded.push(pad) }

    padded
}

pub fn pkcs7_unpad(buffer: &[u8], block_size: u8) -> Option<Vec<u8>> {
    if buffer.len() % block_size as usize == 0 {
        let blocks = buffer.chunks(block_size as usize);
        let length = blocks.len();

        if blocks.clone().last().unwrap() == vec![block_size, block_size] {
            Some(blocks.take(length - 1).flatten().cloned().collect())
        } else {
            let unpadded_last_block = {
                let mut last_block = blocks.clone().last().unwrap().to_vec();
                let pad_byte = last_block[last_block.len() - 1];
                let number_of_pad_bytes = last_block.iter().rev()
                    .take_while(|byte| **byte == pad_byte).count();

                if &last_block[(block_size as usize)-number_of_pad_bytes..] !=
                      vec![number_of_pad_bytes as u8; number_of_pad_bytes] {
                    return None;
                }

                last_block.truncate(block_size as usize - number_of_pad_bytes);
                last_block
            };
            let mut output: Vec<Vec<u8>> = blocks
                .take(length - 1)
                .map(|x| x.to_vec()).collect();

            output.push(unpadded_last_block);
            Some(output.iter().flatten().cloned().collect())
        }
    } else {
        None
    }
}

#[test]
fn verify() {
    let expected_output = "YELLOW SUBMARINE\x04\x04\x04\x04";
    let padded = pkcs7_pad("YELLOW SUBMARINE".as_bytes(), 20);
    assert_eq!(expected_output.as_bytes(), padded);
}
