import os
import sys
import pyshark

from smugon_aes256 import AESCipher


def decrypt_content(file_path, key):
    data = extract_icmp_data(file_path)
    return AESCipher(key).decrypt(data)


def extract_icmp_data(file_path):
    cap = pyshark.FileCapture(file_path, display_filter='icmp')

    out = bytes()
    for packet in cap:
        if 'ICMP' in packet and packet.icmp.type in ['8']:
            try:
                icmp_data_hex = packet.icmp.data
                out += bytes.fromhex(icmp_data_hex)
            except AttributeError:
                continue
    return out


def read_content(file_path: str) -> bytes:
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
    return data


def main():
    assert len(sys.argv) > 2, f"Usage: python {sys.argv[0]} <PCAP_FILE> <KEY>"

    pcap_file = sys.argv[1]
    key_file = sys.argv[2]

    key = read_content(key_file)
    decrypted = decrypt_content(pcap_file, key)
    print(decrypted)


if __name__ == '__main__':
    main()
