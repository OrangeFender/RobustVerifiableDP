pub struct PublicParameters {
    n_b: usize,
}

impl PublicParameters {
    pub fn new(n_b: usize) -> Self {
        Self {
            n_b,
        }
    }

    pub fn get_n_b(&self) -> usize {
        self.n_b
    }
}