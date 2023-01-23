# Is Your Active Directory Pwned?

Check AD passwords against known compromised passwords.

## How to use

### Dump Active Directory accounts

You first need to dump your Active Directory accounts using Mimikatz; this will require special rights,
such as an account that is a member of Administrators, Domain Admins, or Enterprise Admins, as well as
Domain Controller computer accounts. Run PowerShell under that context, and then run the following:

```powershell
PS C:\temp\mimikatz> .\mimikatz "lsadump::dcsync /domain:ad.localdomain /all /csv" exit > hashes.txt
```

Note that if you are running this from a workstation joined to the domain you're dumping accounts from,
you can omit the `/domain` parameter in the command.

You will need to remove the leading and trailing lines in the file; in the final result you must have
only lines describing the accounts.

#### Alternatives to Mimikatz

Other tools can also dump Active Directory accounts and NTLM hashes. All you need in the final file is
the following 4 columns:
 1. ID: This is expected to be the account's Object Relative ID, but any unsigned 64-bit integer (or
 32-bit if you're running this on a 32-bit system) value will be accepted.
 2. Name: The account's name, or any other identifying string you choose to use.
 3. Password Hash: Either the NTLM hash or another hash, provided it matches the hashes in the passwords
 file.
 4. User Account Control flags: This is expected to be the Active Directory `userAccountControl` flags,
 but any unsigned 32-bit integer will be accepted provided that the bit 0x02 is unset for active accounts.

Additional columns may be included; they will be ignored.

## Download HaveIBeenPwned's NTLM hashes

From [HaveIBeenPwned](https://haveibeenpwned.com/Passwords), download the NTLM hashes; be sure to
get the version that has been ordered by hash.

Note that if you're using an alternative method to dump the accounts and password hashes, you need to
ensure that the "Pwned Passwords" file you are using uses the same hashing method; this may mean you
need to source the file from somewhere else.

## Run it!

Compile and run this tool; the easiest way is with Cargo from within the repository's root:

```bash
$ cargo run -- /path/to/passwords.txt /path/to/accounts.txt
```

By default, a new file `pwned.csv` will be created in your current directory; you can specify a different
output file as a third argument. The output file is 4 tab-separated columns:
 1. Account RID
 2. Account Name
 3. User Account Control flags
 4. Pwned count

This output file contains only those accounts whose password was found in the "Pwned Passwords" file.

