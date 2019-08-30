var ut = require("./util");
var crypto = require("crypto");

/**
 *
 * SEED ECB encryption.
 *
 *
 * no padding.
 *
 * @param {string | Buffer} key 16 byte
 * @param {string | Buffer} msg multiple 16 bytes
 * @returns {string} SEED encrypted data
 */
function seed_ecb_encrypt(key, msg) {
  msg = ut.toBuffer(msg);
  key = ut.toBuffer(key);

  if (key.length !== 16) {
    throw Error("key length is invalid. must set to be 16");
  }

  if (msg.length % 16 !== 0) {
    throw Error("Invalid message length, must set to be multiple 16");
  }

  var cipher = crypto.createCipheriv("seed-ecb", key, "");
  cipher.setAutoPadding(false);
  return ut.toHexString(cipher.update(msg));
}

/**
 *
 * SEED CBC decryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte
 * @param {string | Buffer} msg multiple 16 bytes
 * @returns {string} SEED decrypt data
 */
function seed_ecb_decrypt(key, msg) {
  msg = ut.toBuffer(msg);
  key = ut.toBuffer(key);

  if (key.length !== 16) {
    throw Error("key length is invalid. must set to be 16");
  }

  if (msg.length % 16 !== 0) {
    throw Error("Invalid message length, must set to be multiple 16");
  }

  var decipher = crypto.createDecipheriv("seed-ecb", key, "");
  decipher.setAutoPadding(false);

  return ut.toHexString(decipher.update(msg));
}

// key 와 iv에
function addPaddingToKey(buf) {
  if (buf.length < 16) {
    padding = new Buffer.alloc(16 - buf.length, 0);
    const paddedKey = Buffer.concat([buf, padding]);
    // console.log("--패딩--");
    // console.log(paddedKey);
    return paddedKey;
  } else {
    throw Error("키와 iv는 16바이트 이하여야합니다!");
  }
}
/**
 *
 * SEED CBC encryption.
 *
 * no padding.
 *
 * @param {string | Buffer} key 16 byte
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @param {string} mode output mode
 * @returns {string} SEED encrypted data
 */
function seed_cbc_encrypt(key, msg, iv, mode) {
  msg = ut.toBuffer(msg);
  key = ut.toBuffer(key);

  if (key.length !== 16) {
    // console.log("*");
    // console.log("--KEY--");
    key = addPaddingToKey(key);
  }

  if (iv === undefined) {
    iv = new Buffer(16);
    iv.fill(0);
  } else {
    iv = ut.toBuffer(iv);
    // console.log("*");
    // console.log("--IV--");
    // console.log(iv);
  }

  //   console.log("*");
  //   console.log("--TEST--");
  //   console.log(msg);
  console.log("*");

  var cipher = crypto.createCipheriv("seed-cbc", key, iv);
  cipher.setAutoPadding(true);

  return cipher.update(msg, "buffer", mode) + cipher.final(mode);
}

/**
 *
 * SEED CBC decryption.
 *
 *
 * no padding
 *
 * @param {string | Buffer} key 16 byte
 * @param {string | Buffer} msg multiple 16 bytes
 * @param {string | Buffer} [iv] initialize vector
 * @param {string} mode output mode
 * @returns {string} SEED decrypt data
 */
function seed_cbc_decrypt(key, msg, iv, mode) {
  msg = ut.toBuffer(msg);
  key = ut.toBuffer(key);

  if (key.length !== 16) {
    key = addPaddingToKey(key);
  }

  if (iv === undefined) {
    iv = new Buffer(16);
    iv.fill(0);
  } else {
    iv = ut.toBuffer(iv);
  }
  var decipher = crypto.createDecipheriv("seed-cbc", key, iv);
  // decipher.setAutoPadding(false);

  return decipher.update(msg, "buffer", mode) + decipher.final(mode);
}

module.exports = {
  ecb_encrypt: seed_ecb_encrypt,
  ecb_decrypt: seed_ecb_decrypt,
  cbc_encrypt: seed_cbc_encrypt,
  cbc_decrypt: seed_cbc_decrypt
};
