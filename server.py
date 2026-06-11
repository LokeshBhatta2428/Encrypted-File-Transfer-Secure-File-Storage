from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import os
import re
from crypto_utils import verify_hmac, generate_hmac

app = FastAPI()

STORAGE_PATH = "storage/files"
KEY = b'12345678901234567890123456789012'  # TODO: Load from env variable in production

os.makedirs(STORAGE_PATH, exist_ok=True)

MAX_CHUNK_INDEX = 10_000  # Safety cap on chunk count


def safe_filename(filename: str) -> str:
    """
    FIX: Sanitize filename to prevent path traversal attacks.
    Only allow alphanumeric, dots, dashes, underscores.
    """
    sanitized = re.sub(r"[^\w.\-]", "_", os.path.basename(filename))
    if not sanitized or sanitized.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid filename")
    return sanitized


# Upload chunk
@app.post("/upload")
async def upload(
    filename: str = Form(...),
    chunk_index: int = Form(...),
    hmac_value: str = Form(...),
    file: UploadFile = File(...)
):
    # FIX: Sanitize filename to block path traversal
    filename = safe_filename(filename)

    # FIX: Reject unreasonable chunk indices
    if chunk_index < 0 or chunk_index > MAX_CHUNK_INDEX:
        raise HTTPException(status_code=400, detail="Invalid chunk index")

    data = await file.read()

    try:
        mac = bytes.fromhex(hmac_value)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid HMAC hex value")

    if not verify_hmac(data, mac, KEY):
        return {"status": "error", "message": "Integrity check failed"}

    file_path = os.path.join(STORAGE_PATH, f"{filename}.part{chunk_index}")

    with open(file_path, "wb") as f:
        f.write(data)

    return {"status": "chunk received", "chunk_index": chunk_index}


# Merge chunks
@app.post("/merge")
def merge(filename: str):
    # FIX: Sanitize filename
    filename = safe_filename(filename)
    filepath = os.path.join(STORAGE_PATH, filename)

    # FIX: Verify at least chunk 0 exists before merging
    if not os.path.exists(os.path.join(STORAGE_PATH, f"{filename}.part0")):
        raise HTTPException(status_code=400, detail="No chunks found for this file")

    i = 0
    with open(filepath, "wb") as outfile:
        while True:
            part_path = os.path.join(STORAGE_PATH, f"{filename}.part{i}")
            if not os.path.exists(part_path):
                break
            with open(part_path, "rb") as infile:
                outfile.write(infile.read())
            os.remove(part_path)
            i += 1

    return {"status": "file merged", "chunks_merged": i}


# Download file
@app.get("/download")
def download(filename: str):
    # FIX: Sanitize filename to block path traversal
    filename = safe_filename(filename)
    filepath = os.path.join(STORAGE_PATH, filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="File not found")

    with open(filepath, "rb") as f:
        data = f.read()

    # FIX: Include HMAC so the client can verify integrity on download
    mac = generate_hmac(data, KEY)

    return {"data": data.hex(), "hmac": mac.hex()}