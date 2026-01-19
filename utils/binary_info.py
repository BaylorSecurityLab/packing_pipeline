import hashlib
import os
import struct
import sys


def get_sha256(filepath):
    """Calculates SHA256 hash of the file efficiently."""
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read in 4K chunks to handle large files without using too much RAM
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def get_file_size(filepath):
    """Returns human-readable file size."""
    size_bytes = os.path.getsize(filepath)
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:3.2f} {unit} ({os.path.getsize(filepath)} bytes)"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} TB"


def get_pe_architecture(filepath):
    """
    Parses Windows PE headers to determine if x86 or x64.
    Returns 'Unknown' if not a valid PE file.
    """
    try:
        with open(filepath, 'rb') as f:
            # 1. Check for DOS Header 'MZ'
            if f.read(2) != b'MZ':
                return "Not a PE file (No MZ header)"

            # 2. Read value at offset 0x3C to find the PE Header signature
            f.seek(0x3C)
            pe_offset = struct.unpack('<I', f.read(4))[0]

            # 3. Seek to PE Header and check signature 'PE\0\0'
            f.seek(pe_offset)
            if f.read(4) != b'PE\0\0':
                return "Corrupt PE header"

            # 4. Read Machine Type (next 2 bytes)
            machine_type = struct.unpack('<H', f.read(2))[0]

            # Map Machine Type hex to architecture
            # 0x014c = I386 (x86), 0x8664 = AMD64 (x64)
            if machine_type == 0x014c:
                return "x86 (32-bit)"
            elif machine_type == 0x8664:
                return "x64 (64-bit)"
            elif machine_type == 0x01c0:
                return "ARM"
            elif machine_type == 0xaa64:
                return "ARM64"
            else:
                return f"Unknown Arch (Hex: {hex(machine_type)})"

    except Exception as e:
        return f"Error reading headers: {str(e)}"


def analyze_binary(path):
    if not os.path.exists(path):
        print(f"Error: File not found at {path}")
        return

    print(f"--- Analysis for: {os.path.basename(path)} ---")

    # 1. File Size
    print(f"File Size:    {get_file_size(path)}")

    # 2. Architecture
    print(f"Architecture: {get_pe_architecture(path)}")

    # 3. SHA256
    print(f"SHA256:       {get_sha256(path)}")
    print("-" * 40)


if __name__ == "__main__":
    # Check if path is provided via command line, otherwise use default
    if len(sys.argv) > 1:
        target_path = sys.argv[1]

    analyze_binary(target_path)