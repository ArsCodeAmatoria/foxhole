use rand::Rng;

pub struct XorKey {
    key: u8,
}

impl XorKey {
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            key: rng.gen_range(1..=255),
        }
    }

    pub fn encrypt(&self, data: &str) -> Vec<u8> {
        data.bytes()
            .map(|b| b ^ self.key)
            .collect()
    }

    pub fn decrypt(&self, data: &[u8]) -> String {
        data.iter()
            .map(|&b| (b ^ self.key) as char)
            .collect()
    }

    pub fn get_key(&self) -> u8 {
        self.key
    }
}

pub fn generate_obfuscated_string(s: &str) -> (Vec<u8>, u8) {
    let key = XorKey::new();
    (key.encrypt(s), key.get_key())
} 