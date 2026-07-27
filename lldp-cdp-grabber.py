import asyncio
import subprocess
import sys
import os
import argparse
from pathlib import Path
import shutil

try:
    import pyshark
    import psutil
    from InquirerPy import inquirer
except ImportError as e:
    print(f"Missing application dependency: {e}")
    exit(1)

# Arguments for program listed below:
parser = argparse.ArgumentParser(description="List of available arguments for lldp-cdp-grabber.")

parser.add_argument("--pcapinput", type=str, required=False, help="Path to network capture file (optional).")
parser.add_argument("--interface", type=str, help="Interface name")
parser.add_argument("--waitTime", type=int, default=None, help="Time to wait for packets (default: 60 seconds).")
parser.add_argument("--tsharkpath", type=str, default="tshark", help="Path to tshark executable (optional).")

# This prevents --lldp and --cdp from being used together, as they are mutually exclusive options.
group = parser.add_mutually_exclusive_group()
group.add_argument('--lldp', action='store_true', help="Only show LLDP information.")
group.add_argument('--cdp', action='store_true', help="Only show CDP information.")

args = parser.parse_args()

if args.pcapinput:
    if args.interface or args.waitTime:
        parser.error("--pcapinput cannot be used with --interface or --waitTime")

# Rule 2: interface/waitTime require each other and exclude pcapinput
if args.interface or args.waitTime:
    if args.pcapinput:
        parser.error("--interface/--waitTime cannot be used with --pcapinput")

if args.waitTime is None:
    args.waitTime = 60 # Set default wait for live captures to 60 seconds if not specified by user.

global_tshark_path = ""

def check_wireshark():

    # Grabs home directory of user to check for tshark in common locations.
    home_path = Path.home()
    # List of common locations for tshark executable on different operating systems.
    tshark_paths = [args.tsharkpath.replace("\\", "/"), 
                   shutil.which("tshark"),
                   "C:/Program Files/Wireshark/tshark.exe", 
                   "C:/Program Files (x86)/Wireshark/tshark.exe", 
                   str(home_path) + "/AppData/Local/Wireshark/tshark.exe", 
                   str(home_path) + "/AppData/Roaming/Wireshark/tshark.exe",
                   "./App/Wireshark/tshark.exe",
                   "/opt/homebrew/bin/tshark",
                   "/usr/local/bin/tshark",
                   "/Applications/Wireshark.app/Contents/MacOS/tshark",
                   "/opt/local/bin/tshark",
                   "/usr/local/sbin/tshark",
                   "/usr/local/bin/tshark",
                   "/usr/bin/tshark",
                   "/usr/sbin/tshark",
                   "/snap/bin/tshark",
                   "/opt/wireshark/bin/tshark",
                    str(home_path) + "/.local/bin/tshark",
                    str(home_path) + "/bin/tshark"
                   ]

    tshark_path_found = False

    # Sets global variable for tshark path if found in any of the common locations.
    for tshark_path in tshark_paths:
        if tshark_path and Path(tshark_path).is_file():
            tshark_path_found = True
            global global_tshark_path 
            global_tshark_path = tshark_path
            break
    if not tshark_path_found:
        print("Error: tshark not found. Please install Wireshark and ensure tshark is in your PATH or specify the path using --tsharkpath.")
        end_program()

# Function to clear screen.
def clear():
    subprocess.run("cls" if os.name == "nt" else "clear", shell=True)

def end_program():
    input("\nPress enter to exit.")
    sys.exit(1)

def main():
    import json
    import psutil
    import tempfile

    # Set initial variables.
    lldp_fields = []
    cdp_fields = []
    interface_names= []
    lldp_found = False
    cdp_found = False 

    # Check if the specified pcap file exists if provided.
    pcap_file_path = Path(str(args.pcapinput))
    if not pcap_file_path.is_file() and args.pcapinput:
        print("Error: The specified pcap file does not exist.")
        end_program()

    
    default_fields_json = {
    "LLDPfields": [
        {"wireshark_filter": "chassis.id.mac", "display_as": "Switch MAC: ", "uppercase": True},
        {"wireshark_filter": "tlv.system.name", "display_as": "Switch Name: ", "uppercase": False},
        {"wireshark_filter": "port.id", "display_as": "Port ID: ", "uppercase": False},
        {"wireshark_filter": "ieee.802_1.vlan.id", "display_as": "Native VLAN ID: ", "uppercase": False},
        {"wireshark_filter": "ieee.802_1.vlan.name", "display_as": "Native VLAN Name: ", "uppercase": False},
        {"wireshark_filter": "ieee.802_1.port_vlan.id", "display_as": "Available VLANs: ", "uppercase": False}
    ],
    "CDPfields": [
        {"wireshark_filter": "deviceid", "display_as": "Switch Name: ", "uppercase": False},
        {"wireshark_filter": "portid", "display_as": "Switch ID: ", "uppercase": False},
        {"wireshark_filter": "native_vlan", "display_as": "Native VLAN: ", "uppercase": False}
    ]
}

    # Checks if fields.json exists in the current directory. If not, it will automatically create one with default values listed above.
    fields_file_path = Path("fields.json")
    if not fields_file_path.exists():
        fields_file_path.write_text(json.dumps(default_fields_json, indent=2), encoding="utf-8")

    # Imports fields.json file. This will be used to determine which fields to extract from the LLDP and CDP packets.
    # Field options are listed here:
    # - LLDP: https://www.wireshark.org/docs/dfref/l/lldp.html
    # - CDP: https://www.wireshark.org/docs/dfref/c/cdp.html
    # REMOVE cdp. or lldp. prefix from field names before placing in fields.json!
    with open("fields.json") as f:
        fields_json = json.load(f)

    # If no pcap file is provided as well as no interface, the user is prompted to select an interface from a list of available interfaces. 
    # The selected interface is then used for packet capture.
    if not args.pcapinput and not args.interface:
        # Grabs available interfaces from the device.
        interfaces = psutil.net_if_addrs()
        # Extracts the interface names from the interfaces dictionary and appends them to interface_names list.
        for interface_name, interface_addresses in interfaces.items():
            interface_names.append(interface_name)
        # Sets inteface variable to the interface selected by the user.
        interface = inquirer.select(message="=== Select an Interface ===\n",choices=interface_names, qmark="").execute()
        clear()

        # Tests to ensure user has permissions to run packet capture. If not, it will prompt the user to run as sudo or administrator.
        try:
            # Runs tshark capture on selected interface for 1 second.
            subprocess.run([global_tshark_path, "-i", interface, "-a", "duration:1"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, text=True)
        # Checks if error occured when running tshark. 
        except subprocess.CalledProcessError as e:
            stderr = e.stderr.decode().lower()
            # Checks if error was related to permissions issue.
            if "permission" in stderr or "denied" in stderr:
                print("It appears that you do not have permission to capture packets on: " + interface)
                if os.name == "nt":
                    print("Please re-run this program as administrator")
                else:
                    print("Please re-run this program as root or sudo.")
            else:
                print("Error running tshark. Error: ", stderr)
                end_program()

        # Grabs the MAC address of the selected interface and formats it to be uppercase with colons instead of dashes (for windows devices).
        for address in interfaces[interface]:
            if address.family == psutil.AF_LINK:
                interface_mac = address.address.upper().replace("-", ":")
                break
    else:
        # Sets interface variable to the interface provided by the user via command line argument.
        interface = args.interface

    # Runs if user provided --lldp or if neither --lldp nor --cdp were provided.
    # Default behavior is to capture both LLDP and CDP packets
    if args.lldp or (not args.lldp and not args.cdp):

        # If no pcap file is provided, a live capture is performed on the selected interface for LLDP packets.
        if not args.pcapinput:
            print("\n=== Capturing LLDP Packets. This will stop after " + str(args.waitTime) + " seconds if no matching packets are found. Please wait... ===")
            # Sets path for temporary .pcap file. This is put in temp directory.
            output_pcap = os.path.join(tempfile.gettempdir(), 'LLDPcapture.pcap')
            try:
                # Uses tshark to start a live capture of selected interface. 
                # It will only capture lldp packets and will stop if 1 packet is captured or if duration has reached allotted amount.
                # I tried using pyshark.LiveCapture(), however I kept getting event loop errors. This was the fallback resolution.
                subprocess.run([global_tshark_path, "-i", interface, "-f", "ether proto 0x88cc", "-c", "1", "-a", "duration:" + str(args.waitTime), "-w", output_pcap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                # If tshark fails to run, the script will continue unless the user only specified --lldp.
                print("\nError running tshark. Please check your tshark installation and try again.")
                if args.lldp:
                    end_program()
            # Needed to manually create event loops for pyshark.FileCapture().
            loop1 = asyncio.new_event_loop()
            asyncio.set_event_loop(loop1)
            # Attempts to load file capture created from tshark, if it fails the script will continue unless the user only specified --lldp.
            try:
                # Loads file capture, and only filters for lldp packets. 
                lldp_capture = pyshark.FileCapture(output_pcap, display_filter='lldp', eventloop=loop1, tshark_path=global_tshark_path)
            except:
                if args.lldp:
                    print("\nUnable to read packet capture file. Please try capturing again or use a different interface.")
                    end_program()

        else:
            # Event loops for pyshark.FileCapture().
            loop1 = asyncio.new_event_loop()
            asyncio.set_event_loop(loop1)
            # Attempts to load file capture provided by user, if it fails the script will continue unless the user only specified --lldp.
            try:
                # Loads file capture, and only filters for lldp packets.
                lldp_capture = pyshark.FileCapture(args.pcapinput, display_filter='lldp', eventloop=loop1, tshark_path=global_tshark_path)
            except:
                if args.lldp:
                    print ("\nUnable to read packet capture file. Please check the file and try again.")
                    end_program()

        # Attempts to store lldp capture data into a list. If it fails, the script will continue unless the user only specified --lldp.
        try:
            lldp_packets = list(lldp_capture)
        except:
            if args.lldp:
                print("\nError occurred while processing LLDP packets.")
                end_program()
        # Attempts to close event loop created earlier.
        try:
            loop1.run_until_complete(lldp_capture.close_async())
            loop1.close()
        except:
            pass

        # Checks if there are any lldp packets found in the packet capture.
        # If not, the script will continue unless the user specified --lldp.
        try:
            if len(lldp_packets) == 0:
                print("\nNo LLDP packets found in the capture.")
                if args.lldp:
                    end_program()
            else:
                lldp_found = True
        except:
            print("\nError occurred while processing LLDP packets.")
            if args.lldp:
                end_program()


    # Runs if user provided --cdp or if neither --lldp nor --cdp were provided.
    # Default behavior is to capture both LLDP and CDP packets
    if args.cdp or (not args.lldp and not args.cdp):

        if not args.pcapinput:
            print("\n=== Capturing CDP Packets. This will stop after " + str(args.waitTime) + " seconds if no matching packets are found. Please wait... ===")
            output_pcap = os.path.join(tempfile.gettempdir(), 'CDPcapture.pcap')
            try:
                subprocess.run([global_tshark_path, "-i", interface, "-f", "ether dst 01:00:0c:cc:cc:cc", "-c", "1", "-a", "duration:" + str(args.waitTime), "-w", output_pcap], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                print("\nError running tshark. Please check your tshark installation and try again.")
                if args.cdp:
                    end_program()
            loop2 = asyncio.new_event_loop()
            asyncio.set_event_loop(loop2)
            try:
                cdp_capture = pyshark.FileCapture(output_pcap, display_filter='cdp', eventloop=loop2, tshark_path=global_tshark_path)
            except:
                if args.cdp:
                    print("\nUnable to read packet capture file. Please try capturing again or use a different interface.")
                    end_program()
        else:
            loop2 = asyncio.new_event_loop()
            asyncio.set_event_loop(loop2)
            try:
                cdp_capture = pyshark.FileCapture(args.pcapinput, display_filter='cdp', eventloop=loop2, tshark_path=global_tshark_path)
            except:
                if args.cdp:
                    print("\nUnable to read packet capture file. Please check the file and try again.")
                    end_program()

        try:
            cdp_packets = list(cdp_capture)
        except:
            if args.cdp:
                print("\nError occurred while processing CDP packets.")
                end_program()
        try:
            loop2.run_until_complete(cdp_capture.close_async())
            loop2.close()
        except:
            pass

        try:
            if len(cdp_packets) == 0:
                print("\nNo CDP packets found in the capture.")
                if args.cdp:
                    end_program()
            else:
                cdp_found = True
        except:
            print("\nError occurred while processing CDP packets.")
            if args.cdp:
                end_program()

    # Prints out interface information.             
    if not args.pcapinput:
        print("\n=== Interface Information ===\n")
        print(f"Interface: {interface}")
        try:
            print(f"Interface MAC Address: {interface_mac}")
        except:
            pass

    # Exits if both packets dont contain any data.
    if not lldp_found and not cdp_found:
        end_program()

    # Runs if lldp is found.
    if lldp_found:

        # Loads lldp fields from fields.json into lldp_fields list. 
        # This reformats the fields names to be compatible with pyshark. (Replaces periods with underscores.)
        for lldp_config_field in fields_json["LLDPfields"]:
            lldp_fields.append({"wireshark_filter": (lldp_config_field['wireshark_filter'].replace(".", "_")),"display_as": lldp_config_field['display_as'], "uppercase": lldp_config_field['uppercase']})

        print("\n=== LLDP Information Is Listed Below ===\n")

        # Loops through each field type and writes output if a matching field is found in the lldp packet.
        # If the field is not found in the packet, the user will be informed which field is missing.
        for field in lldp_fields:
            try:
                # If the user specified "true" for "uppercase" in fields.json, the field name will be converted to all caps.
                # I put this in here mostly to keep MAC Addresses looking consistent. 
                if field['uppercase']:
                    print(field['display_as'] + (getattr(lldp_packets[0].lldp, field['wireshark_filter']).upper()))
                else:
                    print(field['display_as'] + getattr(lldp_packets[0].lldp, field['wireshark_filter']))
            except:
                print(field['display_as'] + "not seen in packet.")


    # Runs if CDP packet is found.
    if cdp_found:

        for cdp_config_field in fields_json["CDPfields"]:
            cdp_fields.append({"wireshark_filter": (cdp_config_field['wireshark_filter'].replace(".", "_")),"display_as": cdp_config_field['display_as'], "uppercase": cdp_config_field['uppercase']})

        print("\n=== CDP Information Is Listed Below ===\n")

        for field in cdp_fields:
            try:
                if field['uppercase']:
                    print(field['display_as'] + (getattr(cdp_packets[0].cdp, field['wireshark_filter']).upper()))
                else:
                    print(field['display_as'] + getattr(cdp_packets[0].cdp, field['wireshark_filter']))
            except:
                print(field['display_as'] + "not seen in packet.")


if __name__ == "__main__":
    check_wireshark()
    main()
    end_program()