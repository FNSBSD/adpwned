use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

mod consts;

struct User {
    rid: usize,
    username: String,
    password: String,
    uac: u32,
}

impl User {
    fn is_active(&self) -> bool {
        self.uac & consts::UAC_ACCOUNT_DISABLE == 0
    }
}

/// Find `hash` in a file of "pwned" password hashes
///
/// This function performs a binary search to perform the search in `O(log(n))` complexity,
/// utilizing [`Seek`] to scan through the file without reading the entire contents into memory.
///
/// `find_hash` will return an [`Option`] containing the number of times the hashed password has
/// been seen in breaches, or `None` if it has not been seen.
///
/// # Authorship
///
/// The core logic of this function was generated by ChatGPT, though it has since been fixed,
/// optimized, and specialized to this specific purpose by myself.
fn find_hash<R: BufRead + Seek>(reader: &mut R, hash: &str) -> Option<usize> {
    let mut left = 0;
    let mut right = reader.seek(SeekFrom::End(0)).unwrap();

    let target = hash.to_string();
    let mut line = String::new();

    while left <= right {
        let mid = left + (right - left) / 2;
        reader.seek(SeekFrom::Start(mid)).unwrap();
        reader.read_line(&mut line).unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();

        let split_line: Vec<_> = line.trim().split(':').collect();

        match split_line[0].cmp(&target) {
            std::cmp::Ordering::Equal => return Some(split_line[1].parse().unwrap()),
            std::cmp::Ordering::Less => left = mid + 1,
            std::cmp::Ordering::Greater => right = mid - 1,
        }
    }

    None
}


fn main() {
    let hashes = File::open("../hash.csv").expect("Unable to open hashes file");
    let hashreader = BufReader::new(hashes);

    let file = File::open("../pwned-passwords-ntlm-ordered-by-hash-v8.txt").expect("Unable to open pwned passwords file");
    let mut reader = BufReader::new(file);

    for (user, pwned) in hashreader.lines().flatten().filter_map(|line| {
        // let upper = line.to_ascii_uppercase();
        let split: Vec<_> = line.split_whitespace().collect();
        
        let user = User {
            rid: split[0].parse().expect("Failed to parse RID: {line}"),
            username: split[1].to_string(),
            password: split[2].to_ascii_uppercase(),
            uac: split[3].parse().expect("Failed to parse userAccountControl: {line}"),
        };

        if user.is_active() {
            Some(user)
        } else {
            None
        }
    }).filter_map(|user| {
        let pwned = find_hash(&mut reader, user.password.as_str())?;
        Some((user, pwned))
    })
    {
        println!("Pwned! {}'s password has been seen {pwned} times!", user.username);
    }
}