mod nso;
mod util;

use std::io;

fn main() {
    let path = "main.nso";

    match nso::read_nso(path) {
        Ok(header) => {

        }

        Err(e) => eprintln!("error: {}", e),
    }
}
