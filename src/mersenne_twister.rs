struct MersenneTwister {
    index: usize,
    lower_mask: u32,
    state: [u32; Self::N],
    upper_mask: u32,
}

impl MersenneTwister {
    const M: usize = 397;
    const N: usize = 624;
    const R: usize = 31;
    const W: usize = 32;
    const A: u32 = 0x9908B0DF;
    const U: usize = 11;
    const D: u32 = 0xFFFFFFFF;
    const S: usize = 7;
    const B: u32 = 0x9D2C5680;
    const T: usize = 15;
    const C: u32 = 0xEFC60000;
    const L: usize = 18;

    // TODO: will prob need to accept a seed here
    fn new() -> Self {
        let index = Self::N + 1;
        let lower_mask = (1 << Self::R) - 1;
        let state = [0u32; Self::N];
        let upper_mask = !lower_mask & 0x7FFFFFFF; // TODO ehhh

        Self {
            index,
            lower_mask,
            state,
            upper_mask,
        }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= Self::N {
            if self.index > Self::N {
                panic!("generator was never seeded");
            }
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= (y >> Self::U) & Self::D;
        y ^= (y >> Self::S) & Self::B;
        y ^= (y >> Self::T) & Self::C;
        y ^= y >> Self::L;

        self.index += 1;

        y
    }

    fn twist(&mut self) {
        for i in 0..Self::N {
            let x = (self.state[i] & self.upper_mask)
                + (self.state[(i + 1) % Self::N] & self.lower_mask);
            let mut x_a = x >> 1;

            if x % 2 != 0 {
                x_a ^= Self::A;
            }

            self.state[i] = self.state[(i + Self::M) % Self::N] ^ x_a;
        }

        self.index = 0;
    }
}
