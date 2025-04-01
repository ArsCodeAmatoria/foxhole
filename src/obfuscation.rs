use rand::{thread_rng, Rng};
use std::iter::Iterator;

pub enum ObfuscationMethod {
    Xor,
    Rc4,
    Aes,
}

pub struct Obfuscator {
    method: ObfuscationMethod,
    key: Vec<u8>,
}

impl Obfuscator {
    pub fn new(method: ObfuscationMethod) -> Self {
        let key = match method {
            ObfuscationMethod::Xor => vec![thread_rng().gen()],
            ObfuscationMethod::Rc4 => {
                let mut key = vec![0u8; 16];
                thread_rng().fill_bytes(&mut key);
                key
            }
            ObfuscationMethod::Aes => {
                let mut key = vec![0u8; 32];
                thread_rng().fill_bytes(&mut key);
                key
            }
        };
        Self { method, key }
    }

    pub fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        match self.method {
            ObfuscationMethod::Xor => self.xor_encrypt(data),
            ObfuscationMethod::Rc4 => self.rc4_encrypt(data),
            ObfuscationMethod::Aes => self.aes_encrypt(data),
        }
    }

    pub fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        match self.method {
            ObfuscationMethod::Xor => self.xor_decrypt(data),
            ObfuscationMethod::Rc4 => self.rc4_decrypt(data),
            ObfuscationMethod::Aes => self.aes_decrypt(data),
        }
    }

    fn xor_encrypt(&self, data: &[u8]) -> Vec<u8> {
        data.iter().map(|&b| b ^ self.key[0]).collect()
    }

    fn xor_decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.xor_encrypt(data)
    }

    fn rc4_encrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut s: Vec<u8> = (0..256).collect();
        let mut j = 0;
        let key_len = self.key.len();

        // KSA
        for i in 0..256 {
            j = (j + s[i] + self.key[i % key_len]) % 256;
            s.swap(i, j as usize);
        }

        // PRGA
        let mut result = Vec::with_capacity(data.len());
        let mut i = 0;
        let mut j = 0;

        for &byte in data {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            s.swap(i, j as usize);
            let k = s[(s[i].wrapping_add(s[j])) as usize];
            result.push(byte ^ k);
        }

        result
    }

    fn rc4_decrypt(&self, data: &[u8]) -> Vec<u8> {
        self.rc4_encrypt(data)
    }

    fn aes_encrypt(&self, data: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes256;
        use block_padding::{Padding, Pkcs7};
        use generic_array::GenericArray;

        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut blocks = Vec::new();
        let mut current_block = [0u8; 16];
        let mut block_idx = 0;

        for &byte in data {
            current_block[block_idx] = byte;
            block_idx += 1;

            if block_idx == 16 {
                let mut block = GenericArray::from(current_block);
                cipher.encrypt_block(&mut block);
                blocks.extend_from_slice(&block);
                block_idx = 0;
            }
        }

        if block_idx > 0 {
            let padding = 16 - block_idx;
            for i in block_idx..16 {
                current_block[i] = padding as u8;
            }
            let mut block = GenericArray::from(current_block);
            cipher.encrypt_block(&mut block);
            blocks.extend_from_slice(&block);
        }

        blocks
    }

    fn aes_decrypt(&self, data: &[u8]) -> Vec<u8> {
        use aes::cipher::{BlockDecrypt, KeyInit};
        use aes::Aes256;
        use block_padding::{Padding, Pkcs7};
        use generic_array::GenericArray;

        let cipher = Aes256::new(GenericArray::from_slice(&self.key));
        let mut result = Vec::new();
        let mut blocks = data.chunks_exact(16);

        for block in blocks.by_ref() {
            let mut block = GenericArray::from_slice(block).clone();
            cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        if let Some(padding) = result.last() {
            let padding = *padding as usize;
            if padding <= 16 {
                result.truncate(result.len() - padding);
            }
        }

        result
    }

    pub fn get_key(&self) -> &[u8] {
        &self.key
    }
}

pub fn generate_control_flow_obfuscation() -> String {
    let mut code = String::new();
    code.push_str(r#"
    fn obfuscated_jump(condition: bool) -> bool {
        let mut result = false;
        let mut counter = 0;
        
        while counter < 10 {
            if condition {
                result = true;
                break;
            }
            counter += 1;
        }
        
        result
    }
"#);
    code
}

pub fn generate_anti_disassembly() -> String {
    let mut code = String::new();
    code.push_str(r#"
    fn anti_disassembly() {
        let mut x = 0;
        let mut y = 0;
        
        // Insert junk instructions
        for i in 0..100 {
            x = x.wrapping_add(i as u32);
            y = y.wrapping_sub(i as u32);
        }
        
        // Insert conditional jumps
        if x == y {
            x = x.wrapping_mul(2);
        } else {
            y = y.wrapping_div(2);
        }
    }
"#);
    code
} 