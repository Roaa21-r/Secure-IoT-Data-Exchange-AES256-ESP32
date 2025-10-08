#include <WiFi.h>
#include <Preferences.h>
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "esp_system.h"

// -------------------- Pins --------------------
#define TRIG_PIN 25
#define ECHO_PIN 26

// -------------------- Globals --------------------
// We store only derived keys in RAM. Master key is loaded from NVS on boot.
static uint8_t ENC_KEY[32];   // Derived encryption key (from master_key)
static uint8_t MAC_KEY[32];   // Derived MAC key (from master_key)

// Monotonic message counter (anti-replay without relying on wall clock).
// NOTE: Lives in RAM. It resets after power cycle. This is fine if receiver
//       is aware that ctr may restart from 0 after reboot.
static uint32_t msg_counter = 0;

// -------------------- Utilities --------------------
// Trigger ultrasonic and return distance in cm
long readUltrasonic() {
  digitalWrite(TRIG_PIN, LOW);
  delayMicroseconds(2);
  digitalWrite(TRIG_PIN, HIGH);
  delayMicroseconds(10);
  digitalWrite(TRIG_PIN, LOW);
  long duration = pulseIn(ECHO_PIN, HIGH);
  return duration * 0.034 / 2; // cm
}

// Simple PKCS7 pad. Returns total (padded) length.
int pkcs7_pad(const uint8_t* input, int input_len, uint8_t* output, int block_size = 16) {
  int pad_len = block_size - (input_len % block_size);
  int total_len = input_len + pad_len;
  memcpy(output, input, input_len);
  for (int i = input_len; i < total_len; i++) output[i] = (uint8_t)pad_len;
  return total_len;
}

// Generate random IV (16 bytes) using esp_random()
void generateRandomIV(uint8_t* iv, int len) {
  for (int i = 0; i < len; i++) iv[i] = (uint8_t)(esp_random() & 0xFF);
}

// Generate 64-bit nonce (extra uniqueness within the ciphertext)
uint64_t generateNonce64() {
  uint64_t n = ((uint64_t)esp_random() << 32) ^ (uint64_t)esp_random();
  return n;
}

// Compute HMAC-SHA256 (out 32 bytes)
void computeHMAC_SHA256(const uint8_t* key, size_t key_len,
                        const uint8_t* data, size_t data_len,
                        uint8_t out[32]) {
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, info, 1 /* HMAC */);
  mbedtls_md_hmac_starts(&ctx, key, key_len);
  mbedtls_md_hmac_update(&ctx, data, data_len);
  mbedtls_md_hmac_finish(&ctx, out);
  mbedtls_md_free(&ctx);
}

// Derive two keys from a 32B master key:
// ENC_KEY = SHA256("enc|" + master)
// MAC_KEY = SHA256("mac|" + master)
void deriveKeys(const uint8_t master[32]) {
  uint8_t buf[4 + 32];
  memcpy(buf, "enc|", 4); memcpy(buf + 4, master, 32);
  mbedtls_sha256(buf, sizeof(buf), ENC_KEY, 0 /* is224=0 */);

  memcpy(buf, "mac|", 4); memcpy(buf + 4, master, 32);
  mbedtls_sha256(buf, sizeof(buf), MAC_KEY, 0);
}

// Load 32-byte master key from NVS ("secure"/"master_key")
bool loadMasterKeyFromNVS(uint8_t master[32]) {
  Preferences prefs;
  if (!prefs.begin("secure", true)) {
    Serial.println("[SECURE] Failed to open NVS namespace 'secure'");
    return false;
  }
  size_t got = prefs.getBytes("master_key", master, 32);
  prefs.end();
  if (got != 32) {
    Serial.println("[SECURE] master_key not found or invalid length in NVS");
    return false;
  }
  return true;
}

// -------------------- Setup & Loop --------------------
void setup() {
  Serial.begin(115200);
  pinMode(TRIG_PIN, OUTPUT);
  pinMode(ECHO_PIN, INPUT);
  delay(500);

  // Keep radio off for power/security
  WiFi.mode(WIFI_OFF);

  // Load master key from NVS (must be provisioned beforehand)
  uint8_t master[32];
  if (!loadMasterKeyFromNVS(master)) {
    Serial.println("[FATAL] Missing master key in NVS. Provision it first (namespace 'secure', key 'master_key', 32 bytes). Halting.");
    while (true) { delay(1000); }
  }

  // Derive ENC_KEY & MAC_KEY (kept in RAM)
  deriveKeys(master);
  // Wipe 'master' from RAM for safety
  memset(master, 0, sizeof(master));

  Serial.println("[SECURE] Keys ready.");
}

void loop() {
  // 1) Read sensor (float distance)
  float distance = (float)readUltrasonic();

  // 2) Build plaintext: distance(4) + counter(4) + nonce(8) + hmac(32)
  //    Keep 'distance' first to preserve legacy parsing if needed.
  uint8_t plain[4 + 4 + 8 + 32];
  size_t offset = 0;

  // distance as little-endian bytes
  memcpy(plain + offset, &distance, 4); offset += 4;

  // Monotonic message counter (uint32 LE)
  uint32_t ctr = msg_counter;
  memcpy(plain + offset, &ctr, 4); offset += 4;
  msg_counter++; // increase AFTER writing it

  // 64-bit nonce (extra randomness/uniqueness)
  uint64_t nonce = generateNonce64();
  memcpy(plain + offset, &nonce, 8); offset += 8;

  // Compute HMAC over (distance||counter||nonce), store at the tail (32B)
  uint8_t mac[32];
  computeHMAC_SHA256(MAC_KEY, sizeof(MAC_KEY), plain, 4 + 4 + 8, mac);
  memcpy(plain + offset, mac, 32); offset += 32;

  // 3) PKCS7 pad
  uint8_t padded[128]; // ample space
  int padded_len = pkcs7_pad(plain, (int)offset, padded);

  // 4) AES-CBC encrypt with random IV
  uint8_t iv[16];
  generateRandomIV(iv, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  mbedtls_aes_setkey_enc(&aes, ENC_KEY, 256);

  uint8_t encrypted[128];
  uint8_t iv_copy[16];
  memcpy(iv_copy, iv, 16);
  mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv_copy, padded, encrypted);
  mbedtls_aes_free(&aes);

  // 5) Send  framing 
  //    length(2B of padded_len) + IV(16B) + Encrypted(padded_len)
  uint16_t len_to_send = (uint16_t)padded_len;
  Serial.write((uint8_t*)&len_to_send, sizeof(len_to_send));
  Serial.write(iv, 16);
  Serial.write(encrypted, padded_len);

  // Small delay between packets
  delay(2000);
}
