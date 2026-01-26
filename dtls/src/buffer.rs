use std::io::Read;

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

    pub fn read_u24(&mut self) -> Result<u32, String> {
        let head = self.read_u16()?;
        let tail = self.read_u8()?;
        let res = ((head as u32) << 1) + (tail as u32);

        self.pos += 3;

        Ok(res)
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

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), String> {
        self.buf.read_exact(buf).map_err(|err| err.to_string())?;
        self.pos += buf.len();
        Ok(())
    }
}

#[derive(Debug)]
pub struct BufWriter {
    buf: Vec<u8>,
}

impl BufWriter {
    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn write_u16(&mut self, value: u16) {
        self.buf.push((value >> 8) as u8);
        self.buf.push(value as u8);
    }

    pub fn write_u24(&mut self, value: u32) {
        self.buf.push((value >> 16) as u8);
        self.buf.push((value >> 8) as u8);
        self.buf.push(value as u8);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.buf.push((value >> 24) as u8);
        self.buf.push((value >> 16) as u8);
        self.buf.push((value >> 8) as u8);
        self.buf.push(value as u8);
    }
}
