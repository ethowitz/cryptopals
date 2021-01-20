use crate::mersenne_twister::MersenneTwister;

#[test]
fn verify() {
    let seed = 123;
    let mut mt = MersenneTwister::new(seed);
    let numbers: Vec<u64> = (0..5).map(|_| mt.extract_number()).collect();

    assert_eq!(numbers, vec![2991312382, 3062119789, 1228959102, 1840268610, 974319580]);
}
