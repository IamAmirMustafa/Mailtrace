# MailTrax 3.1

**Developed by DEVJIX — [www.devjix.com](https://www.devjix.com)**

Email header and phishing analyzer for the Kali Linux terminal. You give it the raw source of an email; it tells you who really sent it, which servers it passed through, where the sending IP is located, and how likely it is to be phishing.

It is a defensive tool: it only reads the email you give it and looks up public information.

## 1. Install

Put `mailtrax.py` and `install.sh` in one folder, then:

```bash
chmod +x install.sh
./install.sh
```

This copies the tool to `/usr/local/bin/mailtrax` and installs two optional helpers (`python3-dnspython`, `python3-dkim`). After that the command `mailtrax` works from any folder.

Without installing, you can also run it directly: `python3 mailtrax.py mail.eml`

## 2. Get the raw email

MailTrax needs the full original message, not a forwarded copy or a screenshot.

| Mail service | Where to find it |
|---|---|
| Gmail | Open the mail, three dots (top right), **Show original**, then **Download Original** (saves a `.eml`) or **Copy to clipboard** |
| Outlook.com | Three dots, **View**, **View message source** |
| Outlook desktop | File, **Save As** (`.eml`), or File, Properties, Internet headers |
| Yahoo | Three dots, **View raw message** |
| Thunderbird | **Ctrl+U**, or File, Save As, File |

Downloading the `.eml` file is the best option. Copy and paste works too, but the DKIM signature check (`--verify-dkim`) needs the untouched file.

## 3. Basic use

```bash
mailtrax mail.eml              # analyze one file
mailtrax                       # paste the raw mail, then press Ctrl+D
xclip -o -sel clip | mailtrax -   # analyze what is in the clipboard
mailtrax suspicious_mails/     # analyze every .eml / .txt in a folder
```

## 4. All options

| Option | What it does |
|---|---|
| `--html report.html` | Also write a shareable HTML report |
| `--json` | Machine-readable output (for scripts, SIEM, jq) |
| `--ioc` | List IPs, domains, URLs and file hashes to block or report |
| `-q`, `--quiet` | One summary line per mail (good for folders) |
| `--no-net` | Fully offline: only reads the headers, no lookups |
| `--expand` | Follow shortened links (bit.ly etc.) to show the real destination |
| `--verify-dkim` | Cryptographically verify the DKIM signature |
| `--set-key SERVICE KEY` | Save an API key (see section 5) |
| `--show-keys` | Show which API keys are set |
| `--no-color` | Plain text output |
| `--no-anim` | Turn off the animations (banner typing, spinner, risk meter) |

Examples:

```bash
mailtrax mail.eml --ioc --html case-001.html
mailtrax inbox/ -q                      # quick triage of many mails
mailtrax mail.eml --json | jq '.findings[] | select(.severity=="HIGH")'
mailtrax mail.eml --no-net              # nothing leaves your machine
```

Exit codes, for scripting: `0` low risk, `1` suspicious, `2` high risk, `3` could not read the input.

## 5. Optional API keys (free accounts)

The tool works without any key. Keys add reputation data.

| Service | What it adds | Get a key |
|---|---|---|
| `abuseipdb` | Abuse score and report count of the sending IP | abuseipdb.com, Account, API |
| `virustotal` | Detection counts for attachments, link domains, the IP | virustotal.com, profile, API key |
| `urlhaus` | Known malware-hosting domains | auth.abuse.ch |

```bash
mailtrax --set-key abuseipdb  YOUR_KEY
mailtrax --set-key virustotal YOUR_KEY
mailtrax --set-key urlhaus    YOUR_KEY
mailtrax --show-keys
```

Keys are stored in `~/.config/mailtrax/config.json` (readable only by you). You can also use environment variables: `MAILTRAX_ABUSEIPDB`, `MAILTRAX_VIRUSTOTAL`, `MAILTRAX_URLHAUS`.

The free VirusTotal plan allows 4 requests per minute, so MailTrax makes at most 4 VirusTotal lookups per mail. In folder mode you may hit that limit; those lookups are then shown as failed and the rest of the report is unaffected.

## 6. Reading the report

**The highlighted boxes at the top** answer "where did this mail come from?":

- **SENDER'S DEVICE / NETWORK** appears when the sender's mail provider wrote the sender's own IP into the headers (many hosting-company mailboxes and private mail servers do this). It is the WiFi or mobile-data network the sender was on. The location is where the ISP registers that IP: usually the right city, sometimes the ISP's main city, never an exact address.
- **DELIVERED BY MAIL SERVER** is the relay that handed the mail to your provider. Its location is a datacenter and says nothing about where the sender is.
- If only **THIS MAIL CAME FROM** is shown, the sender's provider hides the device IP (Gmail, Outlook.com, Yahoo and most marketing services do) and only the mail server is known.

Each box shows the IP, city and country, latitude and longitude, ISP and a Google Maps link.

**SENDER** shows the visible From address next to the hidden ones. `Return-Path` is where bounces go, `Reply-To` is where your reply would go. In phishing these often differ from From.

**AUTHENTICATION** is what the receiving server (for example Gmail) recorded:

- SPF: was the sending IP allowed to send for that domain?
- DKIM: is the mail signed by the domain, and unchanged in transit?
- DMARC: do SPF/DKIM match the domain shown in From? This is the most important of the three.

**LIVE DNS CHECK** repeats the SPF check against the domain's current DNS records and shows the domain's DMARC policy. If the header says "SPF pass" but the live check disagrees, the header may be forged.

**IP DETAILS** shows up to three addresses:

- Verified sending IP: recorded by your own mail provider, so it cannot be faked. Trust this one.
- Earliest IP in headers: written by the sender's side, can be forged.
- X-Originating-IP: the sender's own device, only present with some providers.

**ROUTE** lists each server hop from sender to you, with delay and whether TLS was used.

**DOMAIN AGE** matters because phishing domains are usually days or weeks old.

**FINDINGS** lists every check with its points:

| Score | Verdict |
|---|---|
| 0 to 19 | Low risk |
| 20 to 49 | Suspicious, verify through another channel |
| 50 to 100 | High risk, likely phishing or spoofed |

Animations run only in an interactive terminal. When you pipe the output to a file or use `--json` / `-q`, they are switched off automatically.

## 7. Limits you should know

- The IP is usually a mail server, not a person. Mail sent from Gmail, Outlook or a marketing service shows that company's server and its location, not the sender's home address.
- A low score is not proof of safety. A hacked genuine account passes SPF, DKIM and DMARC.
- A high score is not proof of crime. Badly configured but honest senders can fail checks.
- IP location is approximate (city level at best).
- Domain age is unavailable for some country domains (for example `.pk`) because their registries do not offer RDAP.
- QR codes and text inside images are not analyzed.
- Outlook `.msg` files are not supported; save as `.eml` instead.

## 8. Safety and privacy

- Never click links or open attachments from a suspicious mail. MailTrax does not open them either; it only hashes attachments and reads link addresses.
- Reports show links "defanged" (`hxxp://bad[.]com`) so they cannot be clicked by accident.
- `--expand` is the only option that contacts the link's server. The attacker could see your IP address, so use it from a VPN or lab VM.
- Online lookups send the IP, domains and file hashes (never the mail content) to: ip-api.com, rdap.org, DNS blacklists, and the services you configured keys for. The ip-api.com lookup is unencrypted HTTP. Use `--no-net` for confidential mail.
- Only analyze mail you are authorized to handle.

## 9. Suggested workflow

1. Save the suspicious mail as `.eml`.
2. `mailtrax mail.eml --ioc --html report.html`
3. Read the HIGH findings first, then check the verified sending IP and domain age.
4. If it is phishing: report it in your mail client, block the IOCs, and report the IP to the abuse contact of its ISP.

## Uninstall

```bash
sudo rm /usr/local/bin/mailtrax
rm -rf ~/.config/mailtrax
```
