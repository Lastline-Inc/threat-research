#!/usr/bin/env python3

import re
import itertools
import logging
import argparse
import sys

HEX_DATA_RE = re.compile(b"[A-Fa-f0-9]{100,}")
HEX_STR_RE = re.compile(b"\"([A-Fa-f0-9]{10,})\"")
XOR_KEY_RE = re.compile(b"\$\w+\s*?=\s*?\'(.*?)\'\s*?;")

POWERHSELL_KEYWORD = b"powershell"
DOTNET_KEYWORD = b"using"

MAX_RECORD_LEN = 8213
HEADER_LEN = 5

def main(args):
    with open(args.input_file, "rb") as fi:
        workbook_data = fi.read()

    # Encrypted powershell is stored as a blob of hex-encoded data inside the workbook.
    hex_data_match = HEX_DATA_RE.search(workbook_data)
    if not hex_data_match:
        logging.error("Unable to find encrypted powershell hex data in workbook stream")
        return -1

    hex_data = hex_data_match.group(0)

    # Maximum size for data in a single cell BIFF record.
    # If there is more data, it'll continue 5 bytes later (skipping the header)
    if len(hex_data) == MAX_RECORD_LEN:
        hex_data_match = HEX_DATA_RE.match(workbook_data[hex_data_match.end(0)+HEADER_LEN:])

        if hex_data_match:
            logging.debug("Hex data is too long and split across two BIFF records")
            hex_data += hex_data_match.group(0)

    if len(hex_data) == MAX_RECORD_LEN*2:
        logging.error("Hex data is too long for this script to handle")
        logging.error("It could either be a parsing error or an unusual payload")
        return -1

    logging.debug(hex_data)
    logging.debug("Hex data len: {}".format(len(hex_data)))

    # un-hexing the encrypted powershell
    try:
        enc_powershell = bytearray().fromhex(hex_data.decode('utf-8'))
    except ValueError:
        logging.error("Something went wrong when unhexing the workbook data")
        return -1

    # The encryption is a basic caesar cipher. However the key changes for each document.
    # The decryption is performed in an obfuscated VBA macro.
    # Since it is known that the script will start by "powershell", the offset can be computed
    # without looking at the macro.
    caesar_shift = ord('p') - enc_powershell[0]
    logging.debug("Caesar cipher shift: {}".format(caesar_shift))

    clear_powershell = bytearray(c + caesar_shift for c in enc_powershell)
    logging.debug(clear_powershell)

    # Sanity check
    # Script always starts by 'powershell'
    if not clear_powershell.startswith(POWERHSELL_KEYWORD):
        logging.error("Powershell payload does not starts with the expected keywork")
        return -1

    # Encrypted .NET code is stored as an hex string in the powershell
    hex_data = HEX_DATA_RE.search(clear_powershell)
    if not hex_data:
        logging.error("Unable to find encrypted .NET hex data in powershell script")
        return -1

    hex_data = hex_data.group(0)
    logging.debug(hex_data)

    # un-hexing the encrypted .NET
    enc_dotnet = bytearray().fromhex(hex_data.decode('utf-8'))

    # Here the data is XOR encrypted.
    # The first variable set in the powershell script is the xor key, this regex extracts it.
    # NB: Since the beginning of the .NET snippet is know, a similar method as above could
    #     have been used to retrieve the key.
    xor_key = XOR_KEY_RE.search(clear_powershell)
    if not xor_key:
        logging.error("Unable to extract the xor key from the powershell script")
        return -1

    xor_key = xor_key.group(1)
    logging.debug(xor_key)

    # Xoring the data with the extracted key
    clear_dotnet = bytearray(c ^ k for c,k in zip(enc_dotnet, itertools.cycle(xor_key)))
    logging.debug(clear_dotnet)

    # Sanity check
    # .NET code always starts with 'using'
    if not clear_dotnet.startswith(DOTNET_KEYWORD):
        logging.error("Dotnet payload does not stats with the expected keywork")
        return -1

    # Extracting encrypted strings from the powershell script
    for hex_str in HEX_STR_RE.finditer(clear_dotnet):
        enc_str = bytearray.fromhex(hex_str.group(1).decode('utf-8'))
        clear_str = bytearray(c ^ k for c,k in zip(enc_str, itertools.cycle(xor_key)))
        logging.debug(clear_str)

        if clear_str.startswith(b"http"):
            print(clear_str.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Malspam network IOC extraction")
    parser.add_argument("-v", "--verbose", help="Verbose mode", action="store_true")
    parser.add_argument("input_file", help="File to decode")
    args = parser.parse_args()

    stdout_handler = logging.StreamHandler(sys.stdout)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(message)s", handlers=[stdout_handler])
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    main(args)
