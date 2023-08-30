use std::{error, net::{Ipv4Addr, Ipv6Addr}};

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

    pub fn step(&mut self, steps: usize) -> Result<()> {
        self.pos += steps;
        Ok(())
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


    fn read_u32(&mut self) -> Result<u32> {
        let res = (self.read_u8()? as u32) << 24 | 
        (self.read_u8()? as u32) << 16 | 
        (self.read_u8()? as u32) << 8 | 
        (self.read_u8()? as u32);

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

#[derive(PartialEq, Eq)]
pub enum RCode {
    NOERROR = 0,
    FORMERR = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP = 4,
    REFUSED = 5
}

impl RCode {
    pub fn from_num(num: u8) -> RCode {
        match num {
            1 => RCode::FORMERR,
            2 => RCode::SERVFAIL,
            3 => RCode::NXDOMAIN,
            4 => RCode::NOTIMP,
            5 => RCode::REFUSED,
            _ => RCode::NOERROR
        }
    }
}

pub struct DNSHeader {
    pub id: u16,

    //flags
    pub recursion_desired: bool, //1 bit
    pub truncation: bool, //1 bit
    pub auth_ans: bool,  //1 bit
    pub opcode: u8, //var
    pub qr: bool, //1 bit
    pub response_code: RCode, //
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool, //1 bit

    pub n_questions: u16,
    pub n_answers: u16,
    pub n_authority_rr: u16,
    pub n_additional_rr: u16
}

impl DNSHeader {
    pub fn new() -> Self {
        Self {
            id: 0,

            recursion_desired: false,
            truncation: false,
            auth_ans: false,
            opcode: 0,
            qr: false,
            response_code: RCode::NOERROR,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,

            n_questions: 0,
            n_answers: 0,
            n_authority_rr: 0,
            n_additional_rr: 0
        }
    }

    pub fn read(&mut self, buffer: &mut BytePacket) -> Result<()> {
            self.id = buffer.read_u16()?;
            
            let flags = buffer.read_u16()?;
            let a = (flags >> 8) as u8;
            let b = (flags & 0xFF) as u8;
            self.recursion_desired = (a & (1 << 0)) > 0;
            self.truncation = (a & (1 << 1)) > 0;
            self.auth_ans = (a & (1 << 2)) > 0;
            self.opcode = (a >> 3) & 0x0F;
            self.qr = (a & (1 << 7)) > 0;

            self.response_code = RCode::from_num(b & 0x0F);
            self.checking_disabled = (b & (1 << 4)) > 0;
            self.authed_data = (b & (1 << 5)) > 0;
            self.z = (b & (1 << 6)) > 0;
            self.recursion_available = (b & (1 << 7)) > 0;

            self.n_questions = buffer.read_u16()?;
            self.n_answers = buffer.read_u16()?;
            self.n_authority_rr = buffer.read_u16()?;
            self.n_additional_rr = buffer.read_u16()?;

            Ok(())
    }
}

//type of record being queried
#[derive(PartialEq, Eq, Debug)]
pub enum QueryRecordType {
    UNKNOWN(u16), 
    A, // A => 1 //IPv4 
}

impl QueryRecordType {
    pub fn to_num(&self) -> u16 {
        match *self {
            QueryRecordType::UNKNOWN(x) => x,
            QueryRecordType::A => 1
        }
    }

    pub fn from_num(num: u16) -> QueryRecordType {
        match num {
            1 => QueryRecordType::A,
            _ => QueryRecordType::UNKNOWN(num)
        }
    }
}

#[derive(PartialEq, Eq, Debug)]
pub struct DNSQuestion {
    pub name: String,
    pub query_type: QueryRecordType,
    pub class: u16
}

impl DNSQuestion {
    pub fn new(name: String, query_type: QueryRecordType) -> Self{
        Self {
            name: name,
            query_type: query_type,
            class: 0
        }
    }

    pub fn read(&mut self, buf: &mut BytePacket) -> Result<()> {    
        self.name = buf.read_qname()?;
        self.query_type = QueryRecordType::from_num(buf.read_u16()?);

        self.class = buf.read_u16()?;

        Ok(())
    }
}

#[derive(PartialEq, Eq, Debug)]
pub enum DNSRRecord {
    UNKNOWN {
        domain: String,
        query_type: u16,
        data_len: u16,
        ttl: u32
    },

    A {
        domain: String,
        addr: Ipv4Addr,
        ttl: u32
    },

    AAAA {
        domain: String,
        addr: Ipv6Addr,
        ttl: u32
    }

    // NS {
    //     domain: String,
    //     host: String,
    //     ttl: u32
    // },

    // MX {
    //     domain: String,
    //     priority: u16,
    //     host: String,
    //     ttl: u32
    // },

    // CNAME {
    //     domain: String,
    //     host: String,
    //     ttl: u32
    // }
}

impl DNSRRecord {
    pub fn read(buf: &mut BytePacket) -> Result<DNSRRecord> {
        let mut domain = buf.read_qname()?;

        let query_type_num = buf.read_u16()?;
        let qtype = QueryRecordType::from_num(query_type_num);

        let class = buf.read_u16()?;
        let ttl = buf.read_u32()?;
        let data_len = buf.read_u16()?;

        match qtype {
            QueryRecordType::A => {
                let raw_addr = buf.read_u32()?;
                let addr = Ipv4Addr::new(
                    ((raw_addr >> 24) & 0xFF) as u8,
                    ((raw_addr >> 16) & 0xFF) as u8,
                    ((raw_addr >> 8) & 0xFF) as u8,
                    ((raw_addr >> 0) & 0xFF) as u8,
                );

                Ok(DNSRRecord::A { 
                        domain: domain, addr: addr, ttl: ttl 
                    })
            }

            QueryRecordType::UNKNOWN(_) => {
                buf.step(data_len as usize)?;

                Ok(DNSRRecord::UNKNOWN { 
                    domain: domain, query_type: query_type_num, data_len: data_len, ttl: ttl 
                })
            }
        }
    }
}

pub struct DNSPacket {
    pub header: DNSHeader,
    pub questions: Vec<DNSQuestion>,
    pub answers: Vec<DNSRRecord>,
    pub authority: Vec<DNSRRecord>,
    pub additional_resources: Vec<DNSRRecord>
}

impl DNSPacket {
    pub fn new() -> Self {
        Self {
            header: DNSHeader::new(),
            questions: Vec::new(),
            answers: Vec::new(),
            authority: Vec::new(),
            additional_resources: Vec::new()
        }
    }

    pub fn from_packet_buffer(buf: &mut BytePacket) -> Result<DNSPacket> {
        let mut result = DNSPacket::new();
        result.header.read(buf);


        for _ in 0..result.header.n_questions {
            let mut question = DNSQuestion::new("".to_string(), QueryRecordType::UNKNOWN(0));

            question.read(buf);
            result.questions.push(question);
        }

        for _ in 0..result.header.n_answers {
            let rec = DNSRRecord::read(buf)?;
            result.answers.push(rec);
        }

        for _ in 0..result.header.n_authority_rr {
            let rec = DNSRRecord::read(buf)?;
            result.authority.push(rec);
        }

        for _ in 0..result.header.n_additional_rr {
            let rec = DNSRRecord::read(buf)?;
            result.additional_resources.push(rec);
        }

        Ok(result)
    }
}