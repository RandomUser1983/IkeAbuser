# IkeAbuser

A simple tool wrapper to automate the enumeration, fingerprinting, and PSK extraction of an IPSec VPN gateway.

Nothing fancy here, just a script I put together to save time during CTFs and while studying for the CPENT. It chains together ike-scan, nmap and hashcat so I don't have to type the same commands over and over.

## Disclaimer

For authorized testing and educational use only. Only run this against machines you own or have explicit permission to test (your lab, CTF boxes, etc). What you do with it is on you.

## What it does

The script walks through the usual steps to test an IKE gateway:

1. Checks with nmap if UDP port 500 or 4500 is open. If not, it stops.
2. Sends the default ike-scan payload in main mode to find a valid transformation. If the defaults don't work, it brute forces all the combinations. If still nothing, it stops.
3. Checks if the gateway answers to a random ID. If it does, ID brute force is pointless, so it stops.
4. If not, it brute forces the IDs from a wordlist using aggressive mode.
5. Once it has a valid ID, it grabs the PSK hash, saves it locally and cracks it offline with hashcat.

If you already know the group ID (maybe you found it somewhere else, like a leaked config), just pass it with `-id` and the script skips straight to the PSK extraction.

## Requirements

You need these installed:

- ike-scan
- nmap
- hashcat
- a password wordlist (rockyou works fine)
- a wordlist for the IDs (the seclists one is good: `/usr/share/seclists/Miscellaneous/ike-groupid.txt`)

## Usage
./IkeAbuser.sh -t <target> -pw <password_wordlist> -iw <id_wordlist> [options]

Note: `-iw` is required unless you pass `-id` with a known group ID, in which case the ID brute force (and its wordlist) are skipped.

### Options

- `-t`, `--target`: target IP (required)
- `-pw`, `--pwd_wordlist`: wordlist for cracking the PSK (required)
- `-iw`, `--id_wordlist`: wordlist for the group IDs (needed if you don't pass `-id`)
- `-id`, `--group_id`: group ID, if you already know it. Skips the ID brute force
- `-p`, `--port`: custom IKE port, if it's not on 500/4500
- `-vi`, `--vendor`: adds vendor info and fingerprinting to the output
- `-o`, `--output`: saves a report of the findings to a file
- `-h`, `--help`: shows the help

### Examples

You already know the ID:
./IkeAbuser.sh -t 10.10.11.87 -id ike@expressway.htb -pw /usr/share/wordlists/rockyou.txt (thanks HTB)

You don't, so brute force it:
./IkeAbuser.sh -t 10.10.11.87 -iw /usr/share/seclists/Miscellaneous/ike-groupid.txt -pw /usr/share/wordlists/rockyou.txt

With vendor info and a saved report:
./IkeAbuser.sh -t 10.10.11.87 -id ike@expressway.htb -pw /usr/share/wordlists/rockyou.txt -vi -o report.txt

## Notes

- The vendor fingerprinting (`-vi`) uses ike-scan's backoff detection, which can take up to a minute. Be patient, it's not stuck.
- The PSK hash is saved as `ike_psk.hash` so you can resume the crack later with your own rules or wordlists if the first run doesn't find it.
