use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom, BufWriter, Write};

mod consts;

struct User {
    rid: usize,
    username: String,
    password: String,
    uac: u32,
}

/// Use a jump search to progressively search through the file for sorted hashes
///
/// Based on the algorithm described at https://www.geeksforgeeks.org/jump-search/
fn jump_search<R: BufRead + Seek>(reader: &mut R, hash: &str) -> (String, usize) {
    let mut segment_start = reader.stream_position().unwrap();
    let n = reader.seek(SeekFrom::End(0)).unwrap();
    let step = ((n as f32).sqrt() as i64).max(1);

    let mut line = String::new();

    reader.seek(SeekFrom::Start(segment_start)).unwrap();

    loop {
        if reader.read_line(&mut line).unwrap() == 0 {
            return ("".to_string(), 0); // Reached the end of the file without finding our target
        }

        let split_line: Vec<_> = line.trim().split(':').collect();

        match split_line[0].cmp(hash) {
            std::cmp::Ordering::Equal => return (split_line[0].to_owned(), split_line[1].parse().unwrap()),
            std::cmp::Ordering::Less => { },
            std::cmp::Ordering::Greater => break,
        }

        segment_start = reader.stream_position().unwrap();
        reader.seek(SeekFrom::Current(step)).unwrap();
        reader.read_line(&mut line).unwrap();
        line.clear();
    }

    // Found the segment where our hash may be, start looking for it linearly
    let stop_at = reader.stream_position().unwrap();
    // Start by backing up to the start of the segment
    reader.seek(SeekFrom::Start(segment_start)).unwrap();
    while reader.stream_position().unwrap() < stop_at {
        line.clear();
        reader.read_line(&mut line).unwrap();

        let split_line: Vec<_> = line.trim().split(':').collect();

        match split_line[0].cmp(hash) {
            std::cmp::Ordering::Equal => return (split_line[0].to_owned(), split_line[1].parse().unwrap()),
            std::cmp::Ordering::Less => { },
            std::cmp::Ordering::Greater => return (split_line[0].to_owned(), split_line[1].parse().unwrap()), // Overshot our target, means it's not here
        }
    }

    unreachable!()
}


fn main() {
    let start = std::time::Instant::now();

    let hashes = File::open("../hash.csv").expect("Unable to open hashes file");
    let hashreader = BufReader::new(hashes);

    let mut total_users = 0;
    let mut users: Vec<_> = hashreader.lines().filter_map(|line| {
        let line = line.ok()?;
        let split: Vec<_> = line.split_whitespace().collect();

        total_users += 1;

        let uac = split[3].parse().expect("Failed to parse userAccountControl: {line}");
        if uac & consts::UAC_ACCOUNT_DISABLE == 0 {
            Some(User {
                rid: split[0].parse().expect("Failed to parse RID: {line}"),
                username: split[1].to_string(),
                password: split[2].to_ascii_uppercase(),
                uac,
            })
        } else {
            None
        }
    }).collect();
    users.sort_unstable_by(|a, b| a.password.cmp(&b.password));
    let active_users = users.len();

    let file = File::open("../pwned-passwords-ntlm-ordered-by-hash-v8.txt").expect("Unable to open pwned passwords file");
    let mut reader = BufReader::new(file);

    let outfile = File::create("pwned.csv").expect("Unable to created output file");
    let mut writer = BufWriter::new(outfile);

    writeln!(&mut writer, "RID\tUser\tuserAccountControl\tPwned").expect("Failed to write to file");

    let mut pwned_users = 0;

    let mut last_hash = String::new();
    let mut last_pwned = 0;

    for (user, pwned) in users.iter().filter_map(|user| {
        if user.password == last_hash {
            pwned_users += 1;
            return Some((user, last_pwned));
        }

        (last_hash, last_pwned) = jump_search(&mut reader, user.password.as_str());

        if user.password == last_hash {
            pwned_users += 1;
            Some((user, last_pwned))
        } else {
            None
        }
    })
    {
        writeln!(&mut writer, "{}\t{}\t{}\t{}", user.rid, user.username, user.uac, pwned).expect("Failed to write to file");
    }

    writer.flush().expect("Failed to finish writing");

    let elapsed = start.elapsed();
    let minutes = elapsed.as_secs() / 60;
    let seconds = elapsed.as_secs_f32() - (minutes * 60) as f32;
    println!("Finished in {minutes} minutes {seconds:.2} seconds");
    println!("{total_users} users; {active_users} active users; {pwned_users} pwned users");
}
