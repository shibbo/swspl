use byteorder::{LittleEndian, ReadBytesExt};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use crate::util;

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
    pub text_compr_size: u32,
    pub rodata_compr_size: u32,
    pub data_compr_size: u32,
    pub embed_offs: u32,
    pub embed_size: u32,
    pub dynstr_offs: u32,
    pub dynstr_size: u32,
    pub dynsym_offs: u32,
    pub dynsym_size: u32,
    pub text_hash: [u8; 0x20],
    pub rodata_hash: [u8; 0x20],
    pub data_hash: [u8; 0x20],
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
            text_compr_size: 0,
            rodata_compr_size: 0,
            data_compr_size: 0,
            embed_offs: 0,
            embed_size: 0,
            dynstr_offs: 0,
            dynstr_size: 0,
            dynsym_offs: 0,
            dynsym_size: 0,
            text_hash: [0; 0x20],
            rodata_hash: [0; 0x20],
            data_hash: [0; 0x20],
        }
    }

    pub fn read<R: Read + Seek>(&mut self, reader: &mut R) -> io::Result<()> {
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

        // sizes of sections for our decompression
        self.text_compr_size = reader.read_u32::<LittleEndian>()?;
        self.rodata_compr_size = reader.read_u32::<LittleEndian>()?;
        self.data_compr_size = reader.read_u32::<LittleEndian>()?;

        // skip reserved data
        // this is a little annoying though...
        let mut buffer = vec![0u8; 0x1C];
        reader.read_exact(&mut buffer)?;

        // embedded data
        self.embed_offs = reader.read_u32::<LittleEndian>()?;
        self.embed_size = reader.read_u32::<LittleEndian>()?;

        // dynamic string
        self.dynstr_offs = reader.read_u32::<LittleEndian>()?;
        self.dynstr_size = reader.read_u32::<LittleEndian>()?;

        // dynamic symbol
        self.dynsym_offs = reader.read_u32::<LittleEndian>()?;
        self.dynsym_size = reader.read_u32::<LittleEndian>()?;

        // section hashes
        reader.read_exact(&mut self.text_hash)?;
        reader.read_exact(&mut self.rodata_hash)?;
        reader.read_exact(&mut self.data_hash)?;

        // time to read our data
        // first we jump to the .text data
        util::jump_to_offs(reader, self.text_seg.offs as u64)?;
        // now we read our bytes (and we know our compresed size)
        let mut text = util::read_bytes(reader, self.text_compr_size as usize)?;
        
        // now we jump to .rodata
        util::jump_to_offs(reader, self.rodata_seg.offs as u64)?;
        let mut rodata = util::read_bytes(reader, self.rodata_compr_size as usize)?;

        // and now .data
        util::jump_to_offs(reader, self.data_seg.offs as u64)?;
        let mut data = util::read_bytes(reader, self.data_compr_size as usize)?;
        
        let text = if self.is_text_compr() {
            println!(".text decompressing...");
            util::decompress_data(&text, self.text_seg.size as usize, self.text_compr_size as usize)?
        }
        else {
            text
        };

        let rodata = if self.is_rodata_compr() {
            println!(".rodata decompressing...");
            util::decompress_data(&rodata, self.rodata_seg.size as usize, self.rodata_compr_size as usize)?
        }
        else {
            rodata
        };

        let data = if self.is_data_compr() {
            println!(".data decompressing...");
            util::decompress_data(&data, self.data_seg.size as usize, self.data_compr_size as usize)?
        }
        else {
            data
        };

        // now let's check our hashes
        if (util::check_hash(&text[..], &self.text_hash)) {
            println!(".text hash verified");
        }
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, ".text hash mismatch"));
        }

        if (util::check_hash(&rodata[..], &self.rodata_hash)) {
            println!(".rodata hash verified");
        }
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, ".rodata hash mismatch"));
        }

        if (util::check_hash(&data[..], &self.data_hash)) {
            println!(".data hash verified");
        }
        else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, ".data hash mismatch"));
        }

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
    let mut reader = &mut file;
    let mut nso_header = NSOHeader::new();
    nso_header.read(&mut reader)?;
    Ok(nso_header)
}