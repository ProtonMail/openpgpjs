/**
 * @fileoverview Provides functions for asymmetric signing and signature verification
 * @module crypto/signature
 */

import { elliptic, rsa, dsa, hmac, postQuantum } from './public_key';
import enums from '../enums';
import util from '../util';
import ShortByteString from '../type/short_byte_string';
import { UnsupportedError } from '../packet/packet';
import { getHashByteLength } from './hash';

/**
 * Parse signature in binary form to get the parameters.
 * The returned values are only padded for EdDSA, since in the other cases their expected length
 * depends on the key params, hence we delegate the padding to the signature verification function.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.2.2|RFC 4880 5.2.2.}
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {Uint8Array} signature - Data for which the signature was created
 * @returns {Promise<Object>} True if signature is valid.
 * @async
 */
export function parseSignatureParams(algo, signature) {
  let read = 0;
  switch (algo) {
    // Algorithm-Specific Fields for RSA signatures:
    // -  MPI of RSA signature value m**d mod n.
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      // The signature needs to be the same length as the public key modulo n.
      // We pad s on signature verification, where we have access to n.
      return { read, signatureParams: { s } };
    }
    // Algorithm-Specific Fields for DSA or ECDSA signatures:
    // -  MPI of DSA or ECDSA value r.
    // -  MPI of DSA or ECDSA value s.
    case enums.publicKey.dsa:
    case enums.publicKey.ecdsa:
    {
      // If the signature payload sizes are unexpected, we will throw on verification,
      // where we also have access to the OID curve from the key.
      const r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      return { read, signatureParams: { r, s } };
    }
    // Algorithm-Specific Fields for legacy EdDSA signatures:
    // -  MPI of an EC point r.
    // -  EdDSA value s, in MPI, in the little endian representation
    case enums.publicKey.eddsaLegacy: {
      // Only Curve25519Legacy is supported (no Curve448Legacy), but the relevant checks are done on key parsing and signature
      // verification: if the signature payload sizes are unexpected, we will throw on verification,
      // where we also have access to the OID curve from the key.
      const r = util.readMPI(signature.subarray(read)); read += r.length + 2;
      const s = util.readMPI(signature.subarray(read)); read += s.length + 2;
      return { read, signatureParams: { r, s } };
    }
    // Algorithm-Specific Fields for Ed25519 signatures:
    // - 64 octets of the native signature
    // Algorithm-Specific Fields for Ed448 signatures:
    // - 114 octets of the native signature
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      const rsSize = 2 * elliptic.eddsa.getPayloadSize(algo);
      const RS = util.readExactSubarray(signature, read, read + rsSize); read += RS.length;
      return { read, signatureParams: { RS } };
    }
    case enums.publicKey.hmac: {
      const mac = new ShortByteString(); read += mac.read(signature.subarray(read));
      return { read, signatureParams: { mac } };
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      const eccSignatureSize = 2 * elliptic.eddsa.getPayloadSize(enums.publicKey.ed25519);
      const eccSignature = util.readExactSubarray(signature, read, read + eccSignatureSize); read += eccSignature.length;
      const mldsaSignature = util.readExactSubarray(signature, read, read + 3309); read += mldsaSignature.length;
      return { read, signatureParams: { eccSignature, mldsaSignature } };
    }
    default:
      throw new UnsupportedError('Unknown signature algorithm.');
  }
}

/**
 * Verifies the signature provided for data using specified algorithms and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Object} signature - Named algorithm-specific signature parameters
 * @param {Object} publicParams - Algorithm-specific public key parameters
 * @param {Object} privateParams - Algorithm-specific private key parameters
 * @param {Uint8Array} data - Data for which the signature was created
 * @param {Uint8Array} hashed - The hashed data
 * @returns {Promise<Boolean>} True if signature is valid.
 * @async
 */
export async function verify(algo, hashAlgo, signature, publicParams, privateParams, data, hashed) {
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const s = util.leftPad(signature.s, n.length); // padding needed for webcrypto and node crypto
      return rsa.verify(hashAlgo, data, s, n, e, hashed);
    }
    case enums.publicKey.dsa: {
      const { g, p, q, y } = publicParams;
      const { r, s } = signature; // no need to pad, since we always handle them as BigIntegers
      return dsa.verify(hashAlgo, r, s, hashed, g, p, q, y);
    }
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicParams;
      const curveSize = new elliptic.CurveWithOID(oid).payloadSize;
      // padding needed for webcrypto
      const r = util.leftPad(signature.r, curveSize);
      const s = util.leftPad(signature.s, curveSize);
      return elliptic.ecdsa.verify(oid, hashAlgo, { r, s }, data, Q, hashed);
    }
    case enums.publicKey.eddsaLegacy: {
      if (getHashByteLength(hashAlgo) < getHashByteLength(enums.hash.sha256)) {
        // Enforce digest sizes, since the constraint was already present in RFC4880bis:
        // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
        // and https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.3-3
        throw new Error('Hash algorithm too weak for EdDSALegacy.');
      }
      const { oid, Q } = publicParams;
      const curveSize = new elliptic.CurveWithOID(oid).payloadSize;
      // When dealing little-endian MPI data, we always need to left-pad it, as done with big-endian values:
      // https://www.ietf.org/archive/id/draft-ietf-openpgp-rfc4880bis-10.html#section-3.2-9
      const r = util.leftPad(signature.r, curveSize);
      const s = util.leftPad(signature.s, curveSize);
      return elliptic.eddsaLegacy.verify(oid, hashAlgo, { r, s }, data, Q, hashed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      if (getHashByteLength(hashAlgo) < getHashByteLength(elliptic.eddsa.getPreferredHashAlgo(algo))) {
        // Enforce digest sizes:
        // - Ed25519: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.4-4
        // - Ed448: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.5-4
        throw new Error('Hash algorithm too weak for EdDSA.');
      }

      const { A } = publicParams;
      return elliptic.eddsa.verify(algo, hashAlgo, signature, data, A, hashed);
    }
    case enums.publicKey.hmac: {
      if (!privateParams) {
        throw new Error('Cannot verify HMAC signature with symmetric key missing private parameters');
      }
      const { cipher: algo } = publicParams;
      const { keyMaterial } = privateParams;
      return hmac.verify(algo.getValue(), keyMaterial, signature.mac.data, hashed);
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      if (!postQuantum.signature.isCompatibleHashAlgo(algo, hashAlgo)) {
        // The signature hash algo MUST have digest larger than 256 bits
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#section-9.4
        throw new Error('Unexpected hash algorithm for PQC signature: digest size too short');
      }
      const { eccPublicKey, mldsaPublicKey } = publicParams;
      return postQuantum.signature.verify(algo, hashAlgo, eccPublicKey, mldsaPublicKey, hashed, signature);
    }
    default:
      throw new Error('Unknown signature algorithm.');
  }
}

/**
 * Creates a signature on data using specified algorithms and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1}
 * and {@link https://tools.ietf.org/html/rfc4880#section-9.4|RFC 4880 9.4}
 * for public key and hash algorithms.
 * @param {module:enums.publicKey} algo - Public key algorithm
 * @param {module:enums.hash} hashAlgo - Hash algorithm
 * @param {Object} publicKeyParams - Algorithm-specific public and private key parameters
 * @param {Object} privateKeyParams - Algorithm-specific public and private key parameters
 * @param {Uint8Array} data - Data to be signed
 * @param {Uint8Array} hashed - The hashed data
 * @returns {Promise<Object>} Signature                      Object containing named signature parameters.
 * @async
 */
export async function sign(algo, hashAlgo, publicKeyParams, privateKeyParams, data, hashed) {
  if (!publicKeyParams || !privateKeyParams) {
    throw new Error('Missing key parameters');
  }
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicKeyParams;
      const { d, p, q, u } = privateKeyParams;
      const s = await rsa.sign(hashAlgo, data, n, e, d, p, q, u, hashed);
      return { s };
    }
    case enums.publicKey.dsa: {
      const { g, p, q } = publicKeyParams;
      const { x } = privateKeyParams;
      return dsa.sign(hashAlgo, hashed, g, p, q, x);
    }
    case enums.publicKey.elgamal:
      throw new Error('Signing with Elgamal is not defined in the OpenPGP standard.');
    case enums.publicKey.ecdsa: {
      const { oid, Q } = publicKeyParams;
      const { d } = privateKeyParams;
      return elliptic.ecdsa.sign(oid, hashAlgo, data, Q, d, hashed);
    }
    case enums.publicKey.eddsaLegacy: {
      if (getHashByteLength(hashAlgo) < getHashByteLength(enums.hash.sha256)) {
        // Enforce digest sizes, since the constraint was already present in RFC4880bis:
        // see https://tools.ietf.org/id/draft-ietf-openpgp-rfc4880bis-10.html#section-15-7.2
        // and https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.3-3
        throw new Error('Hash algorithm too weak for EdDSALegacy.');
      }
      const { oid, Q } = publicKeyParams;
      const { seed } = privateKeyParams;
      return elliptic.eddsaLegacy.sign(oid, hashAlgo, data, Q, seed, hashed);
    }
    case enums.publicKey.ed25519:
    case enums.publicKey.ed448: {
      if (getHashByteLength(hashAlgo) < getHashByteLength(elliptic.eddsa.getPreferredHashAlgo(algo))) {
        // Enforce digest sizes:
        // - Ed25519: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.4-4
        // - Ed448: https://www.rfc-editor.org/rfc/rfc9580.html#section-5.2.3.5-4
        throw new Error('Hash algorithm too weak for EdDSA.');
      }
      const { A } = publicKeyParams;
      const { seed } = privateKeyParams;
      return elliptic.eddsa.sign(algo, hashAlgo, data, A, seed, hashed);
    }
    case enums.publicKey.hmac: {
      const { cipher: algo } = publicKeyParams;
      const { keyMaterial } = privateKeyParams;
      const mac = await hmac.sign(algo.getValue(), keyMaterial, hashed);
      return { mac: new ShortByteString(mac) };
    }
    case enums.publicKey.pqc_mldsa_ed25519: {
      if (!postQuantum.signature.isCompatibleHashAlgo(algo, hashAlgo)) {
        // The signature hash algo MUST have digest larger than 256 bits
        // https://www.ietf.org/archive/id/draft-ietf-openpgp-pqc-10.html#section-9.4
        throw new Error('Unexpected hash algorithm for PQC signature: digest size too short');
      }
      const { eccPublicKey } = publicKeyParams;
      const { eccSecretKey, mldsaSecretKey } = privateKeyParams;
      return postQuantum.signature.sign(algo, hashAlgo, eccSecretKey, eccPublicKey, mldsaSecretKey, hashed);
    }
    default:
      throw new Error('Unknown signature algorithm.');
  }
}
