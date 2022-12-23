use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

fn binary_search_file(filename: &str, target: &str) -> bool {
    let file = File::open(filename).expect("Unable to open file");
    let mut reader = BufReader::new(file);

    let mut left = 0;
    let mut right = reader.seek(SeekFrom::End(0)).unwrap() as usize;

    let target = target.to_string();
    let mut line = String::new();

    while left <= right {
        let mid = left + (right - left) / 2;
        println!("Checking: {left} {mid} {right}");
        reader.seek(SeekFrom::Start(mid as u64)).unwrap();
        reader.read_line(&mut line).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        println!("\t{:?}", line.split(':').next().unwrap());

        match line.trim().cmp(&target) {
            std::cmp::Ordering::Equal => return true,
            std::cmp::Ordering::Less => left = mid + 1,
            std::cmp::Ordering::Greater => right = mid - 1,
        }
    }

    false
}


fn main() {
    let foundit = binary_search_file("../pwned-passwords-ntlm-ordered-by-hash-v8.txt", "FFFFFFBB995590B1568B05376EECE8:2");

    println!("Did we find it? {}", if foundit { "yes" } else { "no" });
}
