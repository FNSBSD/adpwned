use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Seek, SeekFrom, Write};

use clap::Parser;

mod consts;
mod cli;

/// Simple data structure matching Mimikatz's `dcsync` output with the `/csv` switch
struct Account {
    /// Relative ID
    rid: usize,
    /// Account name
    name: String,
    /// Account password
    password: String,
    /// Account `userAccountControl` flags
    ///
    /// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
    uac: u32,
}

/// Use a jump search to progressively search through the file for sorted hashes
///
/// The search file is expected to contain lines in the format `<hash>:<count>`, where `<count>`
/// is the number of times it has been seen in breaches; this is precisely the format for the
/// data files provided by [HaveIBeenPwned]
///
/// For each hash given to us, we jump forward in the sorted file until we hit a larger hash.
/// Then, we jump back to our previous position, and do a simple linear search through that
/// segment until we either find the hash we're looking for, or once again pass it by.
///
/// By leaving the reader's cursor in the position where we last read it, we can pre-sort the
/// hashes we're looking for and then start the search for the next one where we left off,
/// allowing us to very quickly search a very large file for a large number of hashes. This
/// makes this jump search much faster than doing a binary search for each hash, despite a
/// binary search being much faster for a single search.
///
/// Based on the algorithm described at https://www.geeksforgeeks.org/jump-search/
///
/// [HaveIBeenPwned]: https://haveibeenpwned.com/Passwords
fn jump_search<R: BufRead + Seek>(reader: &mut R, hash: &str) -> (String, usize) {
    // Stash our starting point for this search
    let mut segment_start = reader.stream_position().unwrap();
    // Determine the total number of bytes in our reader
    let n = reader.seek(SeekFrom::End(0)).unwrap();
    // Set our step size to be equal to the square root of the total bytes, to a minimum of 1 byte
    let step = ((n as f32).sqrt() as i64).max(1);
    // And return to our starting point
    reader.seek(SeekFrom::Start(segment_start)).unwrap();

    // String buffer to read lines into
    let mut line = String::new();

    // Jump search phase: Jump `step` bytes forward in the file, and see if we've passed our target
    loop {
        // Empty our buffer
        line.clear();
        // Read the next line into our buffer
        if reader.read_line(&mut line).unwrap() == 0 {
            // Reached the end of the file without finding our target
            return ("".to_string(), 0);
        }

        // Split the line and check if we've found our target
        let split_line: Vec<_> = line.trim().split(':').collect();

        match split_line[0].cmp(hash) {
            std::cmp::Ordering::Equal => {
            // Found our target! Return it directly
                return (split_line[0].to_owned(), split_line[1].parse().unwrap())
            }
            // Still "below" our target, keep going
            std::cmp::Ordering::Less => {}
            // Overshot our target, break out of this loop and begin the linear search phase
            std::cmp::Ordering::Greater => break,
        }

        // Store our current position as the start of the next segment
        segment_start = reader.stream_position().unwrap();
        // Jump forward `step` bytes
        reader.seek(SeekFrom::Current(step)).unwrap();
        // We probably landed in the middle of a line, so read to the end of the line
        reader.read_line(&mut line).unwrap();
    }

    // Found the segment where our hash may be, start looking for it linearly
    // Start by backing up to the start of the segment
    reader.seek(SeekFrom::Start(segment_start)).unwrap();
    // Loop infinitely; we'll necessarily stop by the end of the segment because
    // we only drop to this part of the function if we have overshot our target
    loop {
        // Empty our buffer
        line.clear();
        // Read the next line into our buffer
        if reader.read_line(&mut line).unwrap() == 0 {
            // Reached the end of the file without finding our target
            return ("".to_string(), 0);
        }

        // Split the line and check if we've found our target
        let split_line: Vec<_> = line.trim().split(':').collect();

        match split_line[0].cmp(hash) {
            std::cmp::Ordering::Equal => {
            // Found our target! Return it directly
                return (split_line[0].to_owned(), split_line[1].parse().unwrap())
            }
            // Still "below" our target, keep going
            std::cmp::Ordering::Less => {}
            std::cmp::Ordering::Greater => {
            // Overshot our target, means it's not here; return the last hash we did see
                return (split_line[0].to_owned(), split_line[1].parse().unwrap())
            }
        }
    }
}

fn main() {
    let start = std::time::Instant::now();

    let args = cli::Args::parse();

    // The hashes file is expected to be whitespace-delineated and contain (at least) 4 columns:
    // RID  AccountName    HashedPassword  userAccountControl
    // This matches the output of Mimikatz's `dcsync` with the `/csv` option
    let accounts_file = File::open(args.accounts).expect("Unable to open hashes file");
    let accounts_reader = BufReader::new(accounts_file);

    // Pwned passwords file, containing lines in the format `<hash>:<count>`
    let passwords_file = File::open(args.passwords)
        .expect("Unable to open pwned passwords file");
    let mut passwords_reader = BufReader::new(passwords_file);

    // Output CSV file
    let outfile = File::create(args.outfile).expect("Unable to created output file");
    let mut writer = BufWriter::new(outfile);

    // Read our hashes file and create `Account`s from each of the active accounts in the file
    let mut total_accounts = 0;
    let mut accounts: Vec<_> = accounts_reader
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let split: Vec<_> = line.split_whitespace().collect();

            total_accounts += 1;

            let uac = split[3]
                .parse()
                .expect(&format!("Failed to parse userAccountControl: {line}"));
            // Ensure account is active, then build an `Account` object from it
            if uac & consts::UAC_ACCOUNT_DISABLE == 0 {
                Some(Account {
                    rid: split[0].parse().expect("Failed to parse RID: {line}"),
                    name: split[1].to_string(),
                    password: split[2].to_ascii_uppercase(),
                    uac,
                })
            } else {
                None
            }
        })
        .collect();
    // Sort the accounts by their password hashes so we can more efficiently search for them
    accounts.sort_unstable_by(|a, b| a.password.cmp(&b.password));
    let active_accounts = accounts.len();

    // Write column headers to our output file
    writeln!(&mut writer, "RID\tName\tuserAccountControl\tPwned").expect("Failed to write to file");

    let mut pwned_accounts = 0;

    let mut last_hash = String::new();
    let mut last_pwned = 0;

    accounts
        .iter()
        .filter_map(|account| {
            // If this account's password is a duplicate of the previously seen hash, no need to search - it's pwned
            if account.password == last_hash {
                pwned_accounts += 1;
                return Some((account, last_pwned));
            }

            // Search for this account's password hash
            // Note the returned hash may not be the same one we're looking for, indicating it was not found
            (last_hash, last_pwned) = jump_search(&mut passwords_reader, account.password.as_str());

            // Check if the returned hash is actually the one we're looking for
            if account.password == last_hash {
                pwned_accounts += 1;
                Some((account, last_pwned))
            } else {
                None
            }
        })
        .for_each(|(account, pwned)| {
            // Write each user we found into our output CSV
            writeln!(
                &mut writer,
                "{}\t{}\t{}\t{}",
                account.rid, account.name, account.uac, pwned
            )
            .expect("Failed to write to file");
        });

    // Flush the buffered writer to disk
    writer.flush().expect("Failed to finish writing");

    // Output timing and statistics
    let elapsed = start.elapsed();
    let minutes = elapsed.as_secs() / 60;
    let seconds = elapsed.as_secs_f32() - (minutes * 60) as f32;
    println!("Finished in {minutes} minutes {seconds:.2} seconds");
    println!("{total_accounts} accounts; {active_accounts} active accounts; {pwned_accounts} pwned accounts");
}
