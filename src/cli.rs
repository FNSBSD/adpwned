//! This module defines our CLI arguments and parser

use clap::Parser;

/// Check Active Directory accounts for passwords known to have been breached
/// 
/// This tool is designed to check Active Directory accounts that have been dumped by Mimikatz
/// against the NTLM hashes in the HaveIBeenPwned breached passwords file. It is suggested that
/// the accounts be gathered by running the command `lsadump::dcsync /all /csv` in Mimikatz;
/// ensure that you remove any lines from the output file that are not accounts, then run this
/// tool against it.
#[derive(Parser)]
#[command(author, version, about, long_about)]
pub(crate) struct Args {
    /// "Pwned" password hashes file
    /// 
    /// This file must contain lines in the format "<hash>:<count>", where <hash> must be
    /// a hashed password in the same format as in the <ACCOUNTS> file.
    pub(crate) passwords: String,

    /// Account dump file
    /// 
    /// Each line in this file must be whitespace-separated columns, in this order: "Relative ID",
    /// "Account Name", "Account Password", "User Account Control flags"; this is the same format
    /// as Mimikatz's `dcsync` command with the `/csv` option. The account password must be hashed
    /// in the same format as in the <PASSWORDS> file. This file is assumed to not include a header
    /// row.
    /// 
    /// Accounts for which the "ACCOUNT_DISABLE" flag is set in the "User Account Control flags"
    /// will be skipped.
    pub(crate) accounts: String,

    /// Output CSV file
    /// 
    /// Each row of the output will describe an account whose password was found in the
    /// <PASSWORDS> file, with the following columns: "RID" ("Relative ID"), "Name",
    /// "userAccountControl", and "Pwned" containing the number of times the password has been
    /// seen in breaches.
    #[arg(default_value_t = String::from("./pwned.csv"))]
    pub(crate) outfile: String,
}
