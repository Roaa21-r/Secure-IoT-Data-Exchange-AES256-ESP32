import os
import struct
import serial
from Crypto.Cipher import AES
from Crypto.Hash import SHA256, HMAC

# ---------------- Key handling ----------------
def get_master_key_from_env():
    """
    Reads MASTER_KEY_HEX (64 hex chars = 32 bytes) from environment.
    Do NOT hardcode secrets here.
    """
    hexkey = os.getenv("MASTER_KEY_HEX", "").strip()
    if len(hexkey) != 64:
        raise RuntimeError("MASTER_KEY_HEX must be 64 hex chars (32 bytes).")
    try:
        return bytes.fromhex(hexkey)
    except ValueError:
        raise RuntimeError("MASTER_KEY_HEX is not valid hex.")

def derive_keys(master_key: bytes):
    """
    Derive two independent keys from one master:
      ENC_KEY = SHA256(b"enc|" + master)
      MAC_KEY = SHA256(b"mac|" + master)
    """
    enc = SHA256.new(b"enc|" + master_key).digest()
    mac = SHA256.new(b"mac|" + master_key).digest()
    return enc, mac

MASTER = get_master_key_from_env()
ENC_KEY, MAC_KEY = derive_keys(MASTER)

# ---------------- Serial config ----------------
# Adjust COM port as needed
# Keep timeout non-zero so .read() returns if not enough data.
ser = serial.Serial('COM3', 115200, timeout=2)

# ---------------- Helpers ----------------
def pkcs7_unpad(data: bytes) -> bytes:
    """
    Validates and removes PKCS#7 padding. Raises on invalid padding.
    """
    if not data:
        raise ValueError("Empty data for unpad")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError("Invalid PKCS7 padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]

def verify_hmac(mac_key: bytes, msg: bytes, tag: bytes) -> bool:
    """
    Constant-time validation of HMAC-SHA256.
    """
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(msg)
    try:
        h.verify(tag)
        return True
    except ValueError:
        return False

# ---------------- Anti-replay (counter-based) ----------------
# We accept packets only if ctr > last_counter.
# If device reboots and restarts ctr at 0, we treat that as a "session reset".
last_counter = -1

def should_accept_counter(ctr: int) -> bool:
    """
    Accept only strictly increasing counters.
    If the device reboots (ctr back to 0), we accept it and reset the window.
    """
    global last_counter
    if last_counter == -1:
        # First packet ever.
        last_counter = ctr
        return True

    if ctr == 0 and last_counter > 0:
        # Likely a sender reboot → reset tracking window.
        last_counter = 0
        return True

    if ctr > last_counter:
        last_counter = ctr
        return True

    # Otherwise it's a replay or out-of-order (which we do not allow).
    return False

print("[SECURE] Receiver ready (counter-based anti-replay).")

while True:
    # 1) Read 2-byte little-endian length
    length_bytes = ser.read(2)
    if len(length_bytes) < 2:
        continue
    padded_len = int.from_bytes(length_bytes, 'little')

    # 2) Read IV + Encrypted
    need = 16 + padded_len
    raw = ser.read(need)
    if len(raw) < need:
        continue
    
    iv = raw[:16]
    encrypted = raw[16:]

    # 3) AES-CBC decrypt
    cipher = AES.new(ENC_KEY, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(encrypted)

    # 4) Unpad (validate PKCS#7)
    try:
        decrypted = pkcs7_unpad(decrypted_padded)
    except Exception as e:
        print("Padding error:", e)
        continue

    # 5) Parse fields:
    #    distance(4) + counter(4) + nonce(8) + hmac(32)
    if len(decrypted) < 4 + 4 + 8 + 32:
        print("Decrypted payload too short")
        continue

    distance = struct.unpack('<f', decrypted[0:4])[0]
    ctr      = struct.unpack('<I', decrypted[4:8])[0]
    nonce    = struct.unpack('<Q', decrypted[8:16])[0]
    tag      = decrypted[16:48]

    # The HMAC covers: distance(4) + counter(4) + nonce(8) = first 16 bytes.
    signed_part = decrypted[0:16]

    # 6) Verify HMAC (authenticity & integrity)
    if not verify_hmac(MAC_KEY, signed_part, tag):
        print("HMAC verification failed. Dropping packet.")
        continue

    # 7) Anti-replay using strictly increasing counter
    if not should_accept_counter(ctr):
        print(f"Replay/Out-of-order detected: ctr={ctr}, last_ok={last_counter}. Dropping.")
        continue

    # 8) All good → consume the reading
    print(f"Distance: {distance:.2f} cm | ctr={ctr} | nonce={nonce}")
