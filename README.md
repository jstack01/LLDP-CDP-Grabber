# LLDP-CDP Grabber

A lightweight command-line tool for capturing and extracting LLDP and CDP information from network devices.

LLDP (Link Layer Discovery Protocol) and CDP (Cisco Discovery Protocol) packets contain useful switch information such as device names, switch IDs, VLAN information, and port details. This tool uses `tshark` to capture packets and `pyshark` to parse the results.

## Features

* Capture LLDP packets from a live network interface
* Capture CDP packets from a live network interface
* Analyze existing `.pcap` files
* Automatically detect available network interfaces
* Extract customizable LLDP/CDP fields
* Filter output to LLDP-only or CDP-only
* Works on Windows, Linux, and macOS

## Requirements

### Wireshark / tshark

This application requires `tshark`, which is included with Wireshark.

Install Wireshark:

https://www.wireshark.org/download.html

After installation, verify that `tshark` is available:

```bash
tshark --version
```

If `tshark` is installed in a non-standard location, specify it with:

```bash
--tsharkpath /path/to/tshark
```

## Installation

### Using the released binary

Download the appropriate binary from the GitHub Releases page.

Supported platforms:

* Windows x64
* Linux x64
* macOS Apple Silicon

Make the file executable on Linux/macOS:

```bash
chmod +x lldp-cdp-grabber
```

### macOS: Trust the app

On macOS, Gatekeeper may block the app the first time you run it. If you see a message that the app cannot be opened because it is from an unidentified developer, do one of the following:

- In Finder, right-click the app and choose Open. Then confirm the prompt to allow it to run.
- On newer macOS versions, you may also need to open System Settings, go to Privacy & Security, and choose Open Anyway or Allow for the app after the first blocked attempt.
- If you prefer to remove the quarantine flag from the downloaded binary, run:

```bash
xattr -dr com.apple.quarantine /path/to/lldp-cdp-grabber
```

Replace `/path/to/lldp-cdp-grabber` with the actual location of the downloaded app.

### Running from source

Requirements:

* Python 3.13+
* Wireshark/tshark

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Run:

```bash
python lldp-cdp-grabber.py
```

## Usage

### Interactive mode

Run without arguments:

```bash
lldp-cdp-grabber
```

You will be prompted to select a network interface.

The tool will capture both LLDP and CDP packets by default.

---

## Command Line Arguments

### Analyze a packet capture file

```bash
lldp-cdp-grabber --pcapinput capture.pcap
```

### Specify an interface

```bash
lldp-cdp-grabber --interface eth0
```

### Change capture timeout

Default timeout is 60 seconds:

```bash
lldp-cdp-grabber --interface eth0 --waitTime 30
```

### Only capture LLDP

```bash
lldp-cdp-grabber --lldp
```

### Only capture CDP

```bash
lldp-cdp-grabber --cdp
```

### Specify tshark location

```bash
lldp-cdp-grabber --tsharkpath /usr/bin/tshark
```

---

## Customizing Output Fields

The first time the program runs, it creates:

```text
fields.json
```

This file controls which LLDP and CDP fields are displayed.

Example:

```json
{
  "LLDPfields": [
    {
      "wireshark_filter": "tlv.system.name",
      "display_as": "Switch Name: ",
      "uppercase": false
    }
  ]
}
```

Available fields can be found in the Wireshark display filter references:

LLDP:
https://www.wireshark.org/docs/dfref/l/lldp.html

CDP:
https://www.wireshark.org/docs/dfref/c/cdp.html

When adding fields to `fields.json`, remove the `lldp.` or `cdp.` prefix from the Wireshark field name.

Example:

Wireshark field:

```
lldp.tlv.system.name
```

Use:

```json
"tlv.system.name"
```

## Building From Source

The project can be built into a standalone executable using PyInstaller:

```bash
python -m PyInstaller \
  --onefile \
  lldp-cdp-grabber.py
```

The resulting binary will be located in:

```text
dist/
```

## Notes

* Packet capture may require administrator/root privileges depending on the operating system.
* CDP is primarily used by Cisco devices.
* LLDP is an IEEE standard supported by many vendors.
* `tshark` must remain installed separately because it is an external packet capture dependency.

## License

See repository license information.
