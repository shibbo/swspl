use std::io;

mod nso;

fn main() {
    let path = "main.nso";

    match nso::read_nso(path) {
        Ok(header) => {
            // just a bunch of debug statements for now
            println!("NSO Flags: {}", header.flags);
            println!("Text segment addr: {}", header.text_seg.offs);
            println!("rodata segment addr: {}", header.rodata_seg.offs);
            println!("data segment addr: {}", header.data_seg.offs);
            println!("bss size: {}", header.bss_size);

            print!("Module ID: ");
            for byte in header.module_id.iter() {
                // module ids are variable-length so we can cut off
                if *byte == 0 {
                    break
                }
                print!("{:02X}", byte);
            }
            println!();
        }

        Err(e) => eprintln!("error: {}", e),
    }
}
