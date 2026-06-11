import requests
import os
from crypto_utils import encrypt, decrypt, generate_hmac, verify_hmac

SERVER_URL = "http://127.0.0.1:8000"
KEY = b'12345678901234567890123456789012'  # TODO: Load from env variable in production

CHUNK_SIZE = 1024 * 1024  # 1MB


def upload_file(filepath):
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.")
        return

    # FIX: Use os.path.basename for cross-platform filename extraction (was split("/")[-1])
    filename = os.path.basename(filepath)

    file_size = os.path.getsize(filepath)
    print(f"Uploading '{filename}' ({file_size} bytes)...")

    with open(filepath, "rb") as f:
        chunk_index = 0
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break

            encrypted = encrypt(chunk, KEY)
            mac = generate_hmac(encrypted, KEY)

            files = {'file': ('chunk', encrypted)}
            data = {
                'filename': filename,
                'chunk_index': chunk_index,
                'hmac_value': mac.hex()
            }

            try:
                res = requests.post(f"{SERVER_URL}/upload", files=files, data=data, timeout=30)
                res.raise_for_status()
                response_data = res.json()
                if response_data.get("status") == "error":
                    print(f"Server rejected chunk {chunk_index}: {response_data.get('message')}")
                    return
                print(f"Chunk {chunk_index} uploaded: {response_data}")
            except requests.RequestException as e:
                print(f"Upload failed at chunk {chunk_index}: {e}")
                return

            chunk_index += 1

    # Merge chunks on server
    try:
        res = requests.post(f"{SERVER_URL}/merge", params={"filename": filename}, timeout=30)
        res.raise_for_status()
        print(f"Merge result: {res.json()}")
    except requests.RequestException as e:
        print(f"Merge request failed: {e}")
        return

    print("Upload complete!")


def download_file(filename):
    try:
        res = requests.get(f"{SERVER_URL}/download", params={"filename": filename}, timeout=30)
        res.raise_for_status()
    except requests.RequestException as e:
        print(f"Download failed: {e}")
        return

    response_json = res.json()

    if "error" in response_json:
        print(f"Server error: {response_json['error']}")
        return

    data = bytes.fromhex(response_json["data"])

    # FIX: Verify HMAC on downloaded data before decrypting
    if "hmac" not in response_json:
        print("Warning: Server did not provide HMAC — cannot verify integrity.")
    else:
        mac = bytes.fromhex(response_json["hmac"])
        if not verify_hmac(data, mac, KEY):
            print("HMAC verification failed! Data may be tampered. Aborting.")
            return
        print("HMAC verified ✓")

    try:
        decrypted = decrypt(data, KEY)
    except ValueError as e:
        print(f"Decryption failed: {e}")
        return

    # FIX: Use os.path.basename to prevent path traversal in output filename
    safe_name = os.path.basename(filename)
    output_path = f"downloaded_{safe_name}"

    with open(output_path, "wb") as f:
        f.write(decrypted)

    print(f"Download complete! Saved as '{output_path}'")


# CLI Menu
if __name__ == "__main__":
    print("=== Secure File Transfer ===")
    print("1. Upload File")
    print("2. Download File")
    choice = input("Enter choice: ").strip()

    if choice == "1":
        path = input("Enter file path: ").strip()
        upload_file(path)
    elif choice == "2":
        name = input("Enter filename: ").strip()
        download_file(name)
    else:
        print("Invalid choice.")