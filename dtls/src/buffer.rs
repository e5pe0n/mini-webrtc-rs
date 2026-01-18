#[derive(Debug)]
pub struct BufReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> BufReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8, String> {
        if self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            self.pos += 1;
            Ok(b)
        } else {
            Err("out of index".to_string())
        }
    }

    pub fn read_u16(&mut self) -> Result<u16, String> {
        if self.pos < self.buf.len() {
            let b = u16::from_be_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
            self.pos += 2;
            Ok(b)
        } else {
            Err("out of index".to_string())
        }
    }

    pub fn read_u32(&mut self) -> Result<u32, String> {
        if self.pos < self.buf.len() {
            let b = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 2;
            Ok(b)
        } else {
            Err("out of index".to_string())
        }
    }
}
