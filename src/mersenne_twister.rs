pub struct MersenneTwister {
    index: usize,
    inner: [u64; Self::N as usize],
}

impl MersenneTwister {
    const W: u64 = 32;
    const N: usize = 624;
    const M: u64 = 397;
    const R: u64 = 31;
    const A: u64 = 0x9908B0DF;
    const U: u64 = 11;
    const D: u64 = 0xFFFFFFFF;
    const S: u64 = 7;
    const B: u64 = 0x9D2C5680;
    const T: u64 = 15;
    const C: u64 = 0xEFC60000;
    const L: u64 = 18;
    const F: u64 = 1812433253;
    const LOWER_MASK: u64 = (1 << Self::R) - 1;
    const UPPER_MASK: u64 = !Self::LOWER_MASK & (u32::MAX as u64);

    pub fn new(seed: u64) -> Self {
        let index = Self::N;
        let mut inner = [0u64; Self::N as usize];
        inner[0] = seed;

        for i in 1..index {
            inner[i] =
                (u32::MAX as u64) & (Self::F * (inner[i - 1] ^ (inner[i - 1] >> (Self::W - 2))) + (i as u64));
        }

        Self { index, inner }
    }

    pub fn extract_number(&mut self) -> u64 {
        if self.index >= Self::N {
            if self.index > Self::N {
                panic!("this can never happen");
            }

            self.twist();
        }

        let mut y = self.inner[self.index];
        y ^= (y >> Self::U) & Self::D;
        y ^= (y << Self::S) & Self::B;
        y ^= (y << Self::T) & Self::C;
        y ^= y >> Self::L;

        self.index += 1;

        (u32::MAX as u64) & y
    }

    fn twist(&mut self) {
        for i in 0..Self::N {
            let x = (self.inner[i] & Self::UPPER_MASK) + (self.inner[(i+1) % Self::N] & Self::LOWER_MASK);
            let mut x_a = x >> 1;

            if (x % 2) != 0 {
                x_a ^= Self::A;
            }

            self.inner[i] = self.inner[(((i as u64)+Self::M) % (Self::N as u64)) as usize] ^ x_a;
        }

        self.index = 0;
    }
}
