//! CPython Random's MT19937 state/word semantics, without introducing a second seed format.

pub(crate) const MAX_WORDS: u32 = 8192;

pub(crate) struct PythonRandom {
    state: [u32; 624],
    index: usize,
    pub(crate) words: u32,
}

impl PythonRandom {
    pub(crate) fn from_state(state: &[u32]) -> Result<Self, &'static str> {
        if state.len() != 625 || state[624] > 624 {
            return Err("invalid Python Random state");
        }
        let mut words = [0; 624];
        words.copy_from_slice(&state[..624]);
        Ok(Self { state: words, index: state[624] as usize, words: 0 })
    }

    fn next_word(&mut self) -> Result<u32, &'static str> {
        if self.words == MAX_WORDS {
            return Err("random word budget exceeded");
        }
        if self.index == 624 {
            for i in 0..624 {
                let y = (self.state[i] & 0x8000_0000) | (self.state[(i + 1) % 624] & 0x7fff_ffff);
                self.state[i] = self.state[(i + 397) % 624] ^ (y >> 1) ^ if y & 1 != 0 { 0x9908_b0df } else { 0 };
            }
            self.index = 0;
        }
        let mut y = self.state[self.index];
        self.index += 1;
        self.words += 1;
        y ^= y >> 11;
        y ^= (y << 7) & 0x9d2c_5680;
        y ^= (y << 15) & 0xefc6_0000;
        y ^= y >> 18;
        Ok(y)
    }

    pub(crate) fn random(&mut self) -> Result<f64, &'static str> {
        let a = self.next_word()? >> 5;
        let b = self.next_word()? >> 6;
        Ok((f64::from(a) * 67108864.0 + f64::from(b)) / 9007199254740992.0)
    }

    pub(crate) fn uniform(&mut self, low: f64, high: f64) -> Result<f64, &'static str> {
        Ok(low + (high - low) * self.random()?)
    }

    pub(crate) fn centre_index(&mut self) -> Result<usize, &'static str> {
        // Python choice over seven entries uses getrandbits(3), rejecting seven.
        loop {
            let value = self.next_word()? >> 29;
            if value < 7 {
                return Ok(value as usize);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_state() -> Vec<u32> {
        let mut state = vec![5489_u32; 625];
        for i in 1..624 {
            state[i] = 1812433253_u32.wrapping_mul(state[i - 1] ^ (state[i - 1] >> 30)).wrapping_add(i as u32);
        }
        state[624] = 624;
        state
    }

    #[test]
    fn standard_mt19937_words_and_python_53_bit_floats() {
        let state = reference_state();
        let mut rng = PythonRandom::from_state(&state).unwrap();
        for expected in [3499211612, 581869302, 3890346734, 3586334585, 545404204] {
            assert_eq!(rng.next_word().unwrap(), expected);
        }
        let mut rng = PythonRandom::from_state(&state).unwrap();
        assert_eq!(rng.random().unwrap(), 0.8147236863931789);
        assert_eq!(rng.random().unwrap(), 0.9057919370756192);
    }

    #[test]
    fn choice_rejection_and_word_budget_are_bounded() {
        let mut rng = PythonRandom::from_state(&reference_state()).unwrap();
        assert_eq!(rng.centre_index().unwrap(), 6);
        assert_eq!(rng.centre_index().unwrap(), 1);
        assert_eq!(rng.centre_index().unwrap(), 6);
        assert_eq!(rng.words, 4);
        rng.words = MAX_WORDS;
        assert!(rng.random().is_err());
        assert!(PythonRandom::from_state(&[0; 624]).is_err());
        assert!(PythonRandom::from_state(&[625; 625]).is_err());
    }
}
