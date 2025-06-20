// GPG4Browsers - An OpenPGP implementation in javascript
// Copyright (C) 2011 Recurity Labs GmbH
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 3.0 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

import PublicKeyPacket from './public_key';
import { newS2KFromConfig, newS2KFromType } from '../type/s2k';
import { computeDigest, getCipherParams, parsePrivateKeyParams, serializeParams, generateParams, validateParams, getRandomBytes, cipherMode } from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';
import { UnsupportedError, writeTag } from './packet';
import computeHKDF from '../crypto/hkdf';

/**
 * A Secret-Key packet contains all the information that is found in a
 * Public-Key packet, including the public-key material, but also
 * includes the secret-key material after all the public-key fields.
 * @extends PublicKeyPacket
 */
class SecretKeyPacket extends PublicKeyPacket {
  static get tag() {
    return enums.packet.secretKey;
  }

  /**
   * @param {Date} [date] - Creation date
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  constructor(date = new Date(), config = defaultConfig) {
    super(date, config);
    /**
     * Secret-key data
     */
    this.keyMaterial = null;
    /**
     * Indicates whether secret-key data is encrypted. `this.isEncrypted === false` means data is available in decrypted form.
     */
    this.isEncrypted = null;
    /**
     * S2K usage
     * @type {enums.symmetric}
     */
    this.s2kUsage = 0;
    /**
     * S2K object
     * @type {type/s2k}
     */
    this.s2k = null;
    /**
     * Symmetric algorithm to encrypt the key with
     * @type {enums.symmetric}
     */
    this.symmetric = null;
    /**
     * AEAD algorithm to encrypt the key with (if AEAD protection is enabled)
     * @type {enums.aead}
     */
    this.aead = null;
    /**
     * Whether the key is encrypted using the legacy AEAD format proposal from RFC4880bis
     * (i.e. it was encrypted with the flag `config.aeadProtect` in OpenPGP.js v5 or older).
     * This value is only relevant to know how to decrypt the key:
     * if AEAD is enabled, a v4 key is always re-encrypted using the standard AEAD mechanism.
     * @type {Boolean}
     * @private
     */
    this.isLegacyAEAD = null;
    /**
     * Decrypted private parameters, referenced by name
     * @type {Object}
     */
    this.privateParams = null;
    /**
     * `true` for keys whose integrity is already confirmed, based on
     * the AEAD encryption mechanism
     * @type {Boolean}
     * @private
     */
    this.usedModernAEAD = null;
  }

  // 5.5.3.  Secret-Key Packet Formats

  /**
   * Internal parser for private keys as specified in
   * {@link https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-04#section-5.5.3|RFC4880bis-04 section 5.5.3}
   * @param {Uint8Array} bytes - Input string to read the packet from
   * @async
   */
  async read(bytes, config = defaultConfig) {
    // - A Public-Key or Public-Subkey packet, as described above.
    let i = await this.readPublicKey(bytes, config);
    const startOfSecretKeyData = i;

    // - One octet indicating string-to-key usage conventions.  Zero
    //   indicates that the secret-key data is not encrypted.  255 or 254
    //   indicates that a string-to-key specifier is being given.  Any
    //   other value is a symmetric-key encryption algorithm identifier.
    this.s2kUsage = bytes[i++];

    // - Only for a version 5 packet, a one-octet scalar octet count of
    //   the next 4 optional fields.
    if (this.version === 5) {
      i++;
    }

    // - Only for a version 6 packet where the secret key material is
    //   encrypted (that is, where the previous octet is not zero), a one-
    //   octet scalar octet count of the cumulative length of all the
    //   following optional string-to-key parameter fields.
    if (this.version === 6 && this.s2kUsage) {
      i++;
    }

    try {
      // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
      //   one-octet symmetric encryption algorithm.
      if (this.s2kUsage === 255 || this.s2kUsage === 254 || this.s2kUsage === 253) {
        this.symmetric = bytes[i++];

        // - [Optional] If string-to-key usage octet was 253, a one-octet
        //   AEAD algorithm.
        if (this.s2kUsage === 253) {
          this.aead = bytes[i++];
        }

        // - [Optional] Only for a version 6 packet, and if string-to-key usage
        //   octet was 255, 254, or 253, an one-octet count of the following field.
        if (this.version === 6) {
          i++;
        }

        // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
        //   string-to-key specifier.  The length of the string-to-key
        //   specifier is implied by its type, as described above.
        const s2kType = bytes[i++];
        this.s2k = newS2KFromType(s2kType);
        i += this.s2k.read(bytes.subarray(i, bytes.length));

        if (this.s2k.type === 'gnu-dummy') {
          return;
        }
      } else if (this.s2kUsage) {
        this.symmetric = this.s2kUsage;
      }


      if (this.s2kUsage) {
        // OpenPGP.js up to v5 used to support encrypting v4 keys using AEAD as specified by draft RFC4880bis (https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-5.5.3-3.5).
        // This legacy format is incompatible, but fundamentally indistinguishable, from that of the crypto-refresh for v4 keys (v5 keys are always in legacy format).
        // While parsing the key may succeed (if IV and AES block sizes match), key decryption will always
        // fail if the key was parsed according to the wrong format, since the keys are processed differently.
        // Thus, for v4 keys, we rely on the caller to instruct us to process the key as legacy, via config flag.
        this.isLegacyAEAD = this.s2kUsage === 253 && (
          this.version === 5 || (this.version === 4 && config.parseAEADEncryptedV4KeysAsLegacy));
        // - crypto-refresh: If string-to-key usage octet was 255, 254 [..], an initialization vector (IV)
        // of the same length as the cipher's block size.
        // - RFC4880bis (v5 keys, regardless of AEAD): an Initial Vector (IV) of the same length as the
        //   cipher's block size. If string-to-key usage octet was 253 the IV is used as the nonce for the AEAD algorithm.
        // If the AEAD algorithm requires a shorter nonce, the high-order bits of the IV are used and the remaining bits MUST be zero
        if (this.s2kUsage !== 253 || this.isLegacyAEAD) {
          this.iv = bytes.subarray(
            i,
            i + getCipherParams(this.symmetric).blockSize
          );
          this.usedModernAEAD = false;
        } else {
          // crypto-refresh: If string-to-key usage octet was 253 (that is, the secret data is AEAD-encrypted),
          // an initialization vector (IV) of size specified by the AEAD algorithm (see Section 5.13.2), which
          // is used as the nonce for the AEAD algorithm.
          this.iv = bytes.subarray(
            i,
            i + cipherMode.getAEADMode(this.aead).ivLength
          );
          // the non-legacy AEAD encryption mechanism also authenticates public key params; no need for manual validation.
          this.usedModernAEAD = true;
        }

        i += this.iv.length;
      }
    } catch (e) {
      // if the s2k is unsupported, we still want to support encrypting and verifying with the given key
      if (!this.s2kUsage) throw e; // always throw for decrypted keys
      this.unparseableKeyMaterial = bytes.subarray(startOfSecretKeyData);
      this.isEncrypted = true;
    }

    // - Only for a version 5 packet, a four-octet scalar octet count for
    //   the following key material.
    if (this.version === 5) {
      i += 4;
    }

    // - Plain or encrypted multiprecision integers comprising the secret
    //   key data.  These algorithm-specific fields are as described
    //   below.
    this.keyMaterial = bytes.subarray(i);
    this.isEncrypted = !!this.s2kUsage;

    if (!this.isEncrypted) {
      let cleartext;
      if (this.version === 6) {
        cleartext = this.keyMaterial;
      } else {
        cleartext = this.keyMaterial.subarray(0, -2);
        if (!util.equalsUint8Array(util.writeChecksum(cleartext), this.keyMaterial.subarray(-2))) {
          throw new Error('Key checksum mismatch');
        }
      }
      try {
        const { read, privateParams } = await parsePrivateKeyParams(this.algorithm, cleartext, this.publicParams);
        if (read < cleartext.length) {
          throw new Error('Error reading MPIs');
        }
        this.privateParams = privateParams;
      } catch (err) {
        if (err instanceof UnsupportedError) throw err;
        // avoid throwing potentially sensitive errors
        throw new Error('Error reading MPIs');
      }
    }
  }

  /**
   * Creates an OpenPGP key packet for the given key.
   * @returns {Uint8Array} A string of bytes containing the secret key OpenPGP packet.
   */
  write() {
    const serializedPublicKey = this.writePublicKey();
    if (this.unparseableKeyMaterial) {
      return util.concatUint8Array([
        serializedPublicKey,
        this.unparseableKeyMaterial
      ]);
    }

    const arr = [serializedPublicKey];
    arr.push(new Uint8Array([this.s2kUsage]));

    const optionalFieldsArr = [];
    // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
    //   one- octet symmetric encryption algorithm.
    if (this.s2kUsage === 255 || this.s2kUsage === 254 || this.s2kUsage === 253) {
      optionalFieldsArr.push(this.symmetric);

      // - [Optional] If string-to-key usage octet was 253, a one-octet
      //   AEAD algorithm.
      if (this.s2kUsage === 253) {
        optionalFieldsArr.push(this.aead);
      }

      const s2k = this.s2k.write();

      // - [Optional] Only for a version 6 packet, and if string-to-key usage
      //   octet was 255, 254, or 253, an one-octet count of the following field.
      if (this.version === 6) {
        optionalFieldsArr.push(s2k.length);
      }

      // - [Optional] If string-to-key usage octet was 255, 254, or 253, a
      //   string-to-key specifier.  The length of the string-to-key
      //   specifier is implied by its type, as described above.
      optionalFieldsArr.push(...s2k);
    }

    // - [Optional] If secret data is encrypted (string-to-key usage octet
    //   not zero), an Initial Vector (IV) of the same length as the
    //   cipher's block size.
    if (this.s2kUsage && this.s2k.type !== 'gnu-dummy') {
      optionalFieldsArr.push(...this.iv);
    }

    if (this.version === 5 || (this.version === 6 && this.s2kUsage)) {
      arr.push(new Uint8Array([optionalFieldsArr.length]));
    }
    arr.push(new Uint8Array(optionalFieldsArr));

    if (!this.isDummy()) {
      if (!this.s2kUsage) {
        this.keyMaterial = serializeParams(this.algorithm, this.privateParams);
      }

      if (this.version === 5) {
        arr.push(util.writeNumber(this.keyMaterial.length, 4));
      }
      arr.push(this.keyMaterial);

      if (!this.s2kUsage && this.version !== 6) {
        arr.push(util.writeChecksum(this.keyMaterial));
      }
    }

    return util.concatUint8Array(arr);
  }

  /**
   * Check whether secret-key data is available in decrypted form.
   * Returns false for gnu-dummy keys and null for public keys.
   * @returns {Boolean|null}
   */
  isDecrypted() {
    return this.isEncrypted === false;
  }

  /**
   * Check whether the key includes secret key material.
   * Some secret keys do not include it, and can thus only be used
   * for public-key operations (encryption and verification).
   * Such keys are:
   * - GNU-dummy keys, where the secret material has been stripped away
   * - encrypted keys with unsupported S2K or cipher
   */
  isMissingSecretKeyMaterial() {
    return this.unparseableKeyMaterial !== undefined || this.isDummy();
  }

  /**
   * Check whether this is a gnu-dummy key
   * @returns {Boolean}
   */
  isDummy() {
    return !!(this.s2k && this.s2k.type === 'gnu-dummy');
  }

  /**
   * Remove private key material, converting the key to a dummy one.
   * The resulting key cannot be used for signing/decrypting but can still verify signatures.
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   */
  makeDummy(config = defaultConfig) {
    if (this.isDummy()) {
      return;
    }
    if (this.isDecrypted()) {
      this.clearPrivateParams();
    }
    delete this.unparseableKeyMaterial;
    this.isEncrypted = null;
    this.keyMaterial = null;
    this.s2k = newS2KFromType(enums.s2k.gnu, config);
    this.s2k.algorithm = 0;
    this.s2k.c = 0;
    this.s2k.type = 'gnu-dummy';
    this.s2kUsage = 254;
    this.symmetric = enums.symmetric.aes256;
    this.isLegacyAEAD = null;
    this.usedModernAEAD = null;
  }

  /**
   * Encrypt the payload. By default, we use aes256 and iterated, salted string
   * to key specifier. If the key is in a decrypted state (isEncrypted === false)
   * and the passphrase is empty or undefined, the key will be set as not encrypted.
   * This can be used to remove passphrase protection after calling decrypt().
   * @param {String} passphrase
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if encryption was not successful
   * @async
   */
  async encrypt(passphrase, config = defaultConfig) {
    if (this.isDummy()) {
      return;
    }

    if (!this.isDecrypted()) {
      throw new Error('Key packet is already encrypted');
    }

    if (!passphrase) {
      throw new Error('A non-empty passphrase is required for key encryption.');
    }

    this.s2k = newS2KFromConfig(config);
    this.s2k.generateSalt();
    const cleartext = serializeParams(this.algorithm, this.privateParams);
    this.symmetric = enums.symmetric.aes256;

    const { blockSize } = getCipherParams(this.symmetric);

    if (config.aeadProtect) {
      this.s2kUsage = 253;
      this.aead = config.preferredAEADAlgorithm;
      const mode = cipherMode.getAEADMode(this.aead);
      this.isLegacyAEAD = this.version === 5; // v4 is always re-encrypted with standard format instead.
      this.usedModernAEAD = !this.isLegacyAEAD; // legacy AEAD does not guarantee integrity of public key material

      const serializedPacketTag = writeTag(this.constructor.tag);
      const key = await produceEncryptionKey(this.version, this.s2k, passphrase, this.symmetric, this.aead, serializedPacketTag, this.isLegacyAEAD);

      const modeInstance = await mode(this.symmetric, key);
      this.iv = this.isLegacyAEAD ? getRandomBytes(blockSize) : getRandomBytes(mode.ivLength);
      const associateData = this.isLegacyAEAD ?
        new Uint8Array() :
        util.concatUint8Array([serializedPacketTag, this.writePublicKey()]);

      this.keyMaterial = await modeInstance.encrypt(cleartext, this.iv.subarray(0, mode.ivLength), associateData);
    } else {
      this.s2kUsage = 254;
      this.usedModernAEAD = false;
      const key = await produceEncryptionKey(this.version, this.s2k, passphrase, this.symmetric);
      this.iv = getRandomBytes(blockSize);
      this.keyMaterial = await cipherMode.cfb.encrypt(this.symmetric, key, util.concatUint8Array([
        cleartext,
        await computeDigest(enums.hash.sha1, cleartext, config)
      ]), this.iv, config);
    }
  }

  /**
   * Decrypts the private key params which are needed to use the key.
   * Successful decryption does not imply key integrity, call validate() to confirm that.
   * {@link SecretKeyPacket.isDecrypted} should be false, as
   * otherwise calls to this function will throw an error.
   * @param {String} passphrase - The passphrase for this private key as string
   * @throws {Error} if the key is already decrypted, or if decryption was not successful
   * @async
   */
  async decrypt(passphrase) {
    if (this.isDummy()) {
      return false;
    }

    if (this.unparseableKeyMaterial) {
      throw new Error('Key packet cannot be decrypted: unsupported S2K or cipher algo');
    }

    if (this.isDecrypted()) {
      throw new Error('Key packet is already decrypted.');
    }

    let key;
    const serializedPacketTag = writeTag(this.constructor.tag); // relevant for AEAD only
    if (this.s2kUsage === 254 || this.s2kUsage === 253) {
      key = await produceEncryptionKey(
        this.version, this.s2k, passphrase, this.symmetric, this.aead, serializedPacketTag, this.isLegacyAEAD);
    } else if (this.s2kUsage === 255) {
      throw new Error('Encrypted private key is authenticated using an insecure two-byte hash');
    } else {
      throw new Error('Private key is encrypted using an insecure S2K function: unsalted MD5');
    }

    let cleartext;
    if (this.s2kUsage === 253) {
      const mode = cipherMode.getAEADMode(this.aead, true);
      const modeInstance = await mode(this.symmetric, key);
      try {
        const associateData = this.isLegacyAEAD ?
          new Uint8Array() :
          util.concatUint8Array([serializedPacketTag, this.writePublicKey()]);
        cleartext = await modeInstance.decrypt(this.keyMaterial, this.iv.subarray(0, mode.ivLength), associateData);
      } catch (err) {
        if (err.message === 'Authentication tag mismatch') {
          throw new Error('Incorrect key passphrase: ' + err.message);
        }
        throw err;
      }
    } else {
      const cleartextWithHash = await cipherMode.cfb.decrypt(this.symmetric, key, this.keyMaterial, this.iv);

      cleartext = cleartextWithHash.subarray(0, -20);
      const hash = await computeDigest(enums.hash.sha1, cleartext);

      if (!util.equalsUint8Array(hash, cleartextWithHash.subarray(-20))) {
        throw new Error('Incorrect key passphrase');
      }
    }

    try {
      const { privateParams } = await parsePrivateKeyParams(this.algorithm, cleartext, this.publicParams);
      this.privateParams = privateParams;
    } catch (err) {
      throw new Error('Error reading MPIs');
    }
    this.isEncrypted = false;
    this.keyMaterial = null;
    this.s2kUsage = 0;
    this.aead = null;
    this.symmetric = null;
    this.isLegacyAEAD = null;
  }

  /**
   * Checks that the key parameters are consistent
   * @throws {Error} if validation was not successful
   * @async
   */
  async validate() {
    if (this.isDummy()) {
      return;
    }

    if (!this.isDecrypted()) {
      throw new Error('Key is not decrypted');
    }

    if (this.usedModernAEAD) {
      // key integrity confirmed by successful AEAD decryption
      return;
    }

    let validParams;
    try {
      // this can throw if some parameters are undefined
      validParams = await validateParams(this.algorithm, this.publicParams, this.privateParams);
    } catch (_) {
      validParams = false;
    }
    if (!validParams) {
      throw new Error('Key is invalid');
    }
  }

  async generate(bits, curve, symmetric) {
    // The deprecated OIDs for Ed25519Legacy and Curve25519Legacy are used in legacy version 4 keys and signatures.
    // Implementations MUST NOT accept or generate v6 key material using the deprecated OIDs.
    if (this.version === 6 && (
      (this.algorithm === enums.publicKey.ecdh && curve === enums.curve.curve25519Legacy) ||
      this.algorithm === enums.publicKey.eddsaLegacy
    )) {
      throw new Error(`Cannot generate v6 keys of type 'ecc' with curve ${curve}. Generate a key of type 'curve25519' instead`);
    }
    if (this.version !== 6 && this.algorithm === enums.publicKey.pqc_mldsa_ed25519) {
      throw new Error(`Cannot generate v${this.version} signing keys of type 'pqc'. Generate a v6 key instead`);
    }
    const { privateParams, publicParams } = await generateParams(this.algorithm, bits, curve, symmetric);
    this.privateParams = privateParams;
    this.publicParams = publicParams;
    this.isEncrypted = false;
  }

  /**
   * Clear private key parameters
   */
  clearPrivateParams() {
    if (this.isMissingSecretKeyMaterial()) {
      return;
    }

    Object.keys(this.privateParams).forEach(name => {
      const param = this.privateParams[name];
      param.fill(0);
      delete this.privateParams[name];
    });
    this.privateParams = null;
    this.isEncrypted = true;
  }
}

/**
 * Derive encryption key
 * @param {Number} keyVersion - key derivation differs for v5 keys
 * @param {module:type/s2k} s2k
 * @param {String} passphrase
 * @param {module:enums.symmetric} cipherAlgo
 * @param {module:enums.aead} [aeadMode] - for AEAD-encrypted keys only (excluding v5)
 * @param {Uint8Array} [serializedPacketTag] - for AEAD-encrypted keys only (excluding v5)
 * @param {Boolean} [isLegacyAEAD] - for AEAD-encrypted keys from RFC4880bis (v4 and v5 only)
 * @returns encryption key
 */
async function produceEncryptionKey(keyVersion, s2k, passphrase, cipherAlgo, aeadMode, serializedPacketTag, isLegacyAEAD) {
  if (s2k.type === 'argon2' && !aeadMode) {
    throw new Error('Using Argon2 S2K without AEAD is not allowed');
  }
  if (s2k.type === 'simple' && keyVersion === 6) {
    throw new Error('Using Simple S2K with version 6 keys is not allowed');
  }
  const { keySize } = getCipherParams(cipherAlgo);
  const derivedKey = await s2k.produceKey(passphrase, keySize);
  if (!aeadMode || keyVersion === 5 || isLegacyAEAD) {
    return derivedKey;
  }
  const info = util.concatUint8Array([
    serializedPacketTag,
    new Uint8Array([keyVersion, cipherAlgo, aeadMode])
  ]);
  return computeHKDF(enums.hash.sha256, derivedKey, new Uint8Array(), info, keySize);
}

export default SecretKeyPacket;
