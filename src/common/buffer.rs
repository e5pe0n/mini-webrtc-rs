use super::error::Error;
use tracing::debug;

const DEBUG: bool = false;

#[derive(Debug)]
pub struct BufReader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
}

impl<'a> BufReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn rest_len(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn read_u8(&mut self) -> Result<u8, Error> {
        if self.pos < self.buf.len() {
            let b = self.buf[self.pos];
            self.pos += 1;

            if DEBUG {
                debug!("{}/{}", self.pos, self.buf.len());
            }

            Ok(b)
        } else {
            Err(Error::BufferOutOfIndexError {
                pos: self.pos + 1,
                len: self.buf.len(),
            })
        }
    }

    pub fn read_u16(&mut self) -> Result<u16, Error> {
        if self.pos + 2 <= self.buf.len() {
            let b = u16::from_be_bytes(self.buf[self.pos..self.pos + 2].try_into().unwrap());
            self.pos += 2;

            if DEBUG {
                debug!("{}/{}", self.pos, self.buf.len());
            }

            Ok(b)
        } else {
            Err(Error::BufferOutOfIndexError {
                pos: self.pos + 2,
                len: self.buf.len(),
            })
        }
    }

    pub fn read_u24(&mut self) -> Result<u32, Error> {
        let head = self.read_u16()?;
        let tail = self.read_u8()?;
        let res = ((head as u32) << 8) + (tail as u32);

        if DEBUG {
            debug!("{}/{}", self.pos, self.buf.len());
        }

        Ok(res)
    }

    pub fn read_u32(&mut self) -> Result<u32, Error> {
        if self.pos + 4 <= self.buf.len() {
            let b = u32::from_be_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
            self.pos += 4;

            if DEBUG {
                debug!("{}/{}", self.pos, self.buf.len());
            }

            Ok(b)
        } else {
            Err(Error::BufferOutOfIndexError {
                pos: self.pos + 4,
                len: self.buf.len(),
            })
        }
    }

    pub fn read_exact(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        if self.pos + buf.len() > self.buf.len() {
            return Err(Error::BufferOutOfIndexError {
                pos: self.pos + buf.len(),
                len: self.buf.len(),
            });
        }

        buf.copy_from_slice(&self.buf[self.pos..self.pos + buf.len()]);
        self.pos += buf.len();

        if DEBUG {
            debug!("{}/{}", self.pos, self.buf.len());
        }

        Ok(())
    }
}

#[derive(Debug)]
pub struct BufWriter {
    buf: Vec<u8>,
}

impl BufWriter {
    pub fn new() -> Self {
        Self { buf: vec![] }
    }

    pub fn buf_ref(&self) -> &Vec<u8> {
        &self.buf
    }

    pub fn buf(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn write_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    pub fn write_u8_at(&mut self, value: u8, pos: usize) {
        self.buf[pos] = value;
    }

    pub fn write_bytes_at(&mut self, bytes: &[u8], pos: usize) {
        self.buf[pos..pos + bytes.len()].copy_from_slice(bytes);
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

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }
}
