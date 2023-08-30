use std::error;

type Result<T> = std::result::Result<T, Box<dyn error::Error>>;

//UDP packet sized 512 that will be written to and used for communication
pub struct BytePacket {
    pub buf: [u8; 512],
    pos: usize,
}

impl BytePacket {
    pub fn new() -> Self {
        Self {
            buf: [0; 512],
            pos: 0
        }
 
 
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) {
        self.pos = pos;
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= 512 {
            return Err("Read beyond bounds".into());
        }

        let res = self.buf[self.pos];
        self.pos += 1;

        Ok(res)
    }

    fn read_u16(&mut self) -> Result<u16> {
        
        let res = (self.read_u8()? as u16) << 8 | self.read_u8()? as u16 ; //treat the read byte as u16, shift eight bits left i.e. add 8 zeroes and AND with second read byte

        Ok(res)
    }

    //retrieve a byte without changing pos in buffer -> eg. to retrieve label in domain name using pointer
    fn get_u8(&self, pos: usize) -> Result<u8> {
        if pos > 512 {
            return Err("Read beyond bounds".into());
        }

        Ok(self.buf[pos])
    }

    fn get_range(&self, start: usize, len: usize) -> Result<&[u8]> {
        if start + len >= 512 {
            return Err("Read beyond bounds".into());
        }
        
        Ok(&self.buf[start..start + len])
    }

    fn write_u8(&mut self, pos: usize, byte: u8) -> Result<()> {
        if pos > 512 {
            return Err("Write beyond bounds".into());
        }

        self.buf[pos] = byte;
        Ok(())
    }

    // [3]www[6]google[3]com[0] -> labels
    fn read_qname(&mut self) -> Result<String> { 
        let mut delim =  " ";

        let mut jumped = false;
        let mut jumps_max = 5;
        let mut jumps_performed = 0;

        let mut pos = self.pos;

        let mut domain_name: String = String::new();

        loop {
            if jumps_performed > jumps_max {
                return Err("Jumped beyond max limit".into());
            }

            let len_byte = self.get_u8(self.pos)?;

            //check if the length has its 2 MSB set
            if (len_byte & 0xC0) == 0xC0 {
                if !jumped {
                    self.seek(pos + 2); //buf's pos updated
                }   

                let byte2 = self.get_u8(pos + 1)? as u16;
                //to get offset, remove the 2 MSBs and take the two bytes together
                let jump_offset = ( (len_byte ^ 0xC0) as u16 ) << 8 | byte2;

                pos = jump_offset as usize;
                jumped = true;
                jumps_performed += 1;

                continue;
            }

            // if not jump condition
            else {
                
                if len_byte == 0 {
                    break;
                }

                pos += 1;

                domain_name.push_str(delim);

                let buffer = self.get_range(pos, len_byte as usize)?;
                //convert this slice of bytes to string
                domain_name.push_str(&String::from_utf8_lossy(buffer).to_lowercase());

                delim = ".";

                pos += len_byte as usize;
            }   
        }

        if !jumped {
            self.seek(pos);
        }

        Ok(domain_name)
    }   
}

