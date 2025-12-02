"use strict";

/********* External Imports ********/

const {
  stringToBuffer,
  bufferToString,
  encodeBuffer,
  decodeBuffer,
  getRandomBytes,
} = require("./lib");
const { subtle } = require("crypto").webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const AES_KEY_SIZE = 256; // AES-256
const PBKDF2_SALT_LENGTH = 16; // 16 bytes for salt
const AES_GCM_IV_LENGTH = 12; // 12 bytes for AES-GCM IV/nonce

/********* Helper Functions ********/

/**
 * Tạo ra khóa AES-256 từ mật khẩu và salt dùng PBKDF2.
 * Arguments:
 * password: string
 * salt: ArrayBuffer | Uint8Array
 * Return Type: Promise<CryptoKey>
 */
async function deriveKey(password, salt) {
  // 1. Nhập mật khẩu thành Key Object
  const keyMaterial = await subtle.importKey(
    "raw",
    stringToBuffer(password),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  ); // 2. Dùng PBKDF2 để tạo ra khóa AES-GCM

  const aesKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: PBKDF2_ITERATIONS,
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: AES_KEY_SIZE },
    true, // Khóa có thể export được (cần cho việc lưu trữ, nhưng ta sẽ không export nó ở đây)
    ["encrypt", "decrypt"] // Mục đích sử dụng khóa
  );
  return aesKey;
}

/**
 * Mã hóa dữ liệu dùng AES-GCM.
 * Arguments:
 * data: string (dữ liệu cần mã hóa)
 * key: CryptoKey (khóa AES)
 * iv: ArrayBuffer | Uint8Array (IV/Nonce)
 * Return Type: Promise<ArrayBuffer> (ciphertext)
 */
async function encryptData(data, key, iv) {
  const dataBuffer = stringToBuffer(data);
  const encrypted = await subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    dataBuffer
  );
  return encrypted;
}

/**
 * Giải mã dữ liệu dùng AES-GCM.
 * Arguments:
 * cipher: ArrayBuffer | Uint8Array (dữ liệu đã mã hóa)
 * key: CryptoKey (khóa AES)
 * iv: ArrayBuffer | Uint8Array (IV/Nonce)
 * Return Type: Promise<string> (plaintext)
 */
async function decryptData(cipher, key, iv) {
  try {
    const decrypted = await subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      cipher
    );
    return bufferToString(decrypted);
  } catch (e) {
    // Thường xảy ra lỗi nếu IV/Key/Ciphertext bị sai (ví dụ: mật khẩu sai)
    throw new Error("Decryption failed. Invalid password or corrupted data.");
  }
}

/**
 * Tính SHA-256 checksum của một string.
 * Arguments:
 * data: string
 * Return Type: Promise<string> (checksum hex string)
 */
async function computeChecksum(data) {
  const dataBuffer = stringToBuffer(data);
  const hash = await subtle.digest("SHA-256", dataBuffer);
  return encodeBuffer(hash); // Trả về chuỗi hex
}

/********* Implementation ********/
class Keychain {
  /**
   * Khởi tạo Keychain.
   * Arguments:
   * aesKey: CryptoKey
   * salt: ArrayBuffer
   * kvsIv: ArrayBuffer
   * kvs: Object (Key-Value Store đã giải mã)
   * Return Type: void
   */
  constructor(aesKey, salt, kvsIv, kvs) {
    this.data = {
      // Thông tin công khai (được lưu trữ trong repr)
      salt: encodeBuffer(salt), // Salt (đã mã hóa base64)
      kvsIv: encodeBuffer(kvsIv), // IV cho KVS (đã mã hóa base64)
    };
    this.secrets = {
      // Thông tin bí mật (chỉ có trong bộ nhớ)
      aesKey: aesKey, // Khóa AES
      kvs: kvs || {}, // Key-Value Store đã giải mã
    };
  }
  /** * Tạo ra một keychain mới với KVS rỗng.
   */

  static async init(password) {
    // 1. Tạo Salt ngẫu nhiên và IV ngẫu nhiên cho KVS
    const salt = getRandomBytes(PBKDF2_SALT_LENGTH);
    const kvsIv = getRandomBytes(AES_GCM_IV_LENGTH); // 2. Tạo khóa AES từ mật khẩu và salt

    const aesKey = await deriveKey(password, salt); // 3. Khởi tạo KVS rỗng

    const emptyKvs = {}; // 4. Trả về đối tượng Keychain mới

    return new Keychain(aesKey, salt, kvsIv, emptyKvs);
  }
  /**
   * Tải trạng thái keychain từ repr.
   */

  static async load(password, repr, trustedDataCheck) {
    // 1. Parse repr
    let parsedRepr;
    try {
      parsedRepr = JSON.parse(repr);
    } catch (e) {
      throw new Error("Invalid repr format: Not a valid JSON.");
    } // Cấu trúc của parsedRepr: { salt: string, kvsIv: string, kvs: Object (placeholder), kvsCipher: string } // Lấy kvsCipher (ciphertext) để giải mã.

    const {
      salt: encodedSalt,
      kvsIv: encodedKvsIv,
      kvsCipher: encodedKvsCipher, // Lấy từ key mới được thêm
    } = parsedRepr; // 2. Decode Salt và IV

    const salt = decodeBuffer(encodedSalt);
    const kvsIv = decodeBuffer(encodedKvsIv);
    const kvsCipher = decodeBuffer(encodedKvsCipher); // 3. Tạo khóa AES từ mật khẩu và salt

    const aesKey = await deriveKey(password, salt); // 4. Giải mã KVS Ciphertext

    const decryptedKvsJson = await decryptData(kvsCipher, aesKey, kvsIv); // 5. Tính Checksum (nếu có trustedDataCheck)

    if (trustedDataCheck) {
      const computedCheck = await computeChecksum(repr);

      if (computedCheck !== trustedDataCheck) {
        throw new Error("Integrity check failed: Checksum mismatch.");
      }
    } // 6. Parse KVS đã giải mã

    let kvs;
    try {
      kvs = JSON.parse(decryptedKvsJson);
    } catch (e) {
      throw new Error("Corrupted KVS data: Cannot parse decrypted content.");
    } // 7. Trả về Keychain

    return new Keychain(aesKey, salt, kvsIv, kvs);
  }
  /**
   * Trả về JSON serialization của keychain.
   */

  async dump() {
    // 1. Serialize KVS thành chuỗi JSON
    const kvsJson = JSON.stringify(this.secrets.kvs); // 2. Mã hóa KVS JSON

    const kvsIv = decodeBuffer(this.data.kvsIv); // Lấy IV đã lưu
    const kvsCipher = await encryptData(kvsJson, this.secrets.aesKey, kvsIv);
    const encodedKvsCipher = encodeBuffer(kvsCipher); // Mã hóa base64 // 🔑 SỬA LỖI BẢO MẬT: Mã hóa Tên miền cho đối tượng placeholder

    const kvs_placeholder = {}; // Thay vì dùng key plaintext, ta dùng Base64 encoding của key
    for (const key in this.secrets.kvs) {
      const encodedKey = encodeBuffer(stringToBuffer(key)); // Mã hóa tên miền
      kvs_placeholder[encodedKey] = true; // Giá trị không quan trọng
    } // 3. Tạo JSON object chứa thông tin cần lưu
    const reprObj = {
      salt: this.data.salt,
      kvsIv: this.data.kvsIv,
      kvs: kvs_placeholder, // Đối tượng placeholder với key đã mã hóa Base64
      kvsCipher: encodedKvsCipher, // Dữ liệu mã hóa thực tế
    }; // 4. Serialize repr object thành chuỗi JSON (arr[0])

    const repr = JSON.stringify(reprObj); // 5. Tính SHA-256 checksum (arr[1]) trên chuỗi repr

    const checksum = await computeChecksum(repr); // 6. Trả về [repr, checksum]

    return [repr, checksum];
  }
  /**
   * Lấy dữ liệu (string) tương ứng với domain name.
   */

  async get(name) {
    return this.secrets.kvs[name] || null;
  }
  /** * Chèn/Cập nhật domain và dữ liệu vào KVS.
   */

  async set(name, value) {
    this.secrets.kvs[name] = value;
  }
  /**
   * Xóa record khỏi password manager.
   */

  async remove(name) {
    if (this.secrets.kvs[name] !== undefined) {
      delete this.secrets.kvs[name];
      return true;
    }
    return false;
  }
}

module.exports = { Keychain };
