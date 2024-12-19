use byteorder::{LittleEndian, ReadBytesExt};
use std::io::{self, Read};

#[derive(Debug)]
pub struct NSOSegment {
    pub offs: u32,
    pub mem_offs: u32,
    pub size: u32,
}

impl NSOSegment {
    pub fn read<R: Read>(&mut self, reader: &mut R) -> io::Result<()> {
        self.offs = reader.read_u32::<LittleEndian>()?;
        self.mem_offs = reader.read_u32::<LittleEndian>()?;
        self.size = reader.read_u32::<LittleEndian>()?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct NSOHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub flags: u32,
    pub text_seg: NSOSegment,
    pub rodata_seg: NSOSegment,
    pub data_seg: NSOSegment,
    pub module_name_offs: u32,
    pub module_name_size: u32,
    pub bss_size: u32,
    pub module_id: [u8; 0x20],
}

impl NSOHeader {
    pub fn new() -> Self {
        NSOHeader {
            magic: [0, 0, 0, 0],
            version: 0,
            flags: 0,
            text_seg: NSOSegment { offs: 0, mem_offs: 0, size: 0 },
            rodata_seg: NSOSegment { offs: 0, mem_offs: 0, size: 0 },
            data_seg: NSOSegment { offs: 0, mem_offs: 0, size: 0 },
            module_name_offs: 0,
            module_name_size: 0,
            bss_size: 0,
            module_id: [0; 0x20],
        }
    }

    pub fn read<R: Read>(&mut self, reader: &mut R) -> io::Result<()> {
        reader.read_exact(&mut self.magic)?;
        self.version = reader.read_u32::<LittleEndian>()?;
        // skip reserved
        reader.read_exact(&mut [0u8; 4])?;
        // flags that determine if we need to decompress data
        self.flags = reader.read_u32::<LittleEndian>()?;
        // text segment information
        self.text_seg.read(reader)?;
        self.module_name_offs = reader.read_u32::<LittleEndian>()?;
        // read-only data (rodata) segment
        self.rodata_seg.read(reader)?;
        self.module_name_size = reader.read_u32::<LittleEndian>()?;
        // data segment
        self.data_seg.read(reader)?;
        self.bss_size = reader.read_u32::<LittleEndian>()?;
        // module id
        reader.read_exact(&mut self.module_id)?;

        Ok(())
    }

    pub fn is_text_compr(&self) -> bool {
        (self.flags & 0x1) != 0
    }

    pub fn is_rodata_compr(&self) -> bool {
        ((self.flags >> 1) & 0x1) != 0
    }

    pub fn is_data_compr(&self) -> bool {
        ((self.flags >> 2) & 0x1) != 0
    }

    pub fn is_text_hashcheck(&self) -> bool {
        ((self.flags >> 3) & 0x1) != 0
    }

    pub fn is_rodata_hashcheck(&self) -> bool {
        ((self.flags >> 4) & 0x1) != 0
    }

    pub fn is_data_hashcheck(&self) -> bool {
        ((self.flags >> 5) & 0x1) != 0
    }
}

pub fn read_nso(path: &str) -> io::Result<NSOHeader> {
    let mut file = std::fs::File::open(path)?;
    let mut nso_header = NSOHeader::new();
    nso_header.read(&mut file)?;
    Ok(nso_header)
}