use crate::common::buffer::BufWriter;

pub struct ChangeCipherSpec {}

impl ChangeCipherSpec {
    pub fn encode(&self, writer: &mut BufWriter) {
        writer.write_u8(0x01);
    }
}
