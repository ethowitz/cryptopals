use std::fs;
use std::cmp::Ordering;
use std::convert::TryFrom;
use super::challenge1::Base64;
use super::challenge2;
use super::challenge3;
use super::challenge5;

fn get_hamming_distance(buffer1: &[u8], buffer2: &[u8]) -> Result<usize, &'static str> {
    let count_bits = |byte| (0..8).fold(0, |acc, n| acc + (((1 << n) & byte) >> n) as usize);

    challenge2::xor(buffer1, buffer2).map(|buffer| {
        buffer.iter().fold(0, |acc, byte| acc + count_bits(*byte))
    })
}

fn find_key(buffer: &[u8]) -> Vec<u8> {
    const MAX_KEYSIZE: usize = 40;

    let keysize = (1..MAX_KEYSIZE).min_by(|keysize1, keysize2| {
        let get_average_hamming_distance = |keysize: usize| {
            let number_of_blocks = buffer.len() / keysize;
            let hamming_distances = (0..(number_of_blocks-1)).map(|n| {
                get_hamming_distance(&buffer[n*keysize..(n+1)*keysize],
                    &buffer[(n+1)*keysize..(n+2)*keysize]).unwrap()
            });
            
            hamming_distances.sum::<usize>() as f64 / number_of_blocks as f64 / keysize as f64
        };
        let average_hamming_distance1 = get_average_hamming_distance(*keysize1);
        let average_hamming_distance2 = get_average_hamming_distance(*keysize2);

        average_hamming_distance1.partial_cmp(&average_hamming_distance2)
            .unwrap_or(Ordering::Equal)
    }).unwrap();

    let blocks = buffer.chunks(keysize);
    let transposed_blocks = (0..blocks.len()).map(|n: usize| -> Vec<u8> {
        blocks.clone().filter_map(|block| block.get(n)).copied().collect()
    });

    transposed_blocks
        .take(keysize)
        .map(|block| challenge3::find_key(&block)[0])
        .collect()
}

// INTUITION
// 1. finding the keysize and transposing the blocks gives you blocks of bytes that were all
//    XOR'd with the same byte
// 2. once we have the single-character key for each transposed block, we can un-transpose one
//    "cycle" of keys to get the original key
// *  This approach makes cryptanalysis easier because we create blocks of bytes whose letter 
//    frequencies don't change with the application of the key
fn find_plaintext(buffer: &[u8]) -> Vec<u8> {
    let key = find_key(buffer);
    challenge5::repeating_key_xor(&key, buffer)
}

#[test]
fn test_get_hamming_distance() {
    let buffer1 = "this is a test".as_bytes();
    let buffer2 = "wokka wokka!!!".as_bytes();
    let expected_hamming_distance = 37;
    assert_eq!(expected_hamming_distance, get_hamming_distance(buffer1, buffer2).unwrap());
}

#[test]
fn verify() {
    let raw = fs::read_to_string("./src/set1/6.txt").unwrap();
    let base64 = Base64::try_from(raw.replace("\n", "").as_str()).unwrap();

    let expected_plaintext = "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while \
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

    let plaintext = String::from_utf8(find_plaintext(&base64.to_bytes())).unwrap();
    assert_eq!(expected_plaintext, plaintext);
}
