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

// The GPG4Browsers crypto interface

/**
 * @fileoverview Provides functions for asymmetric encryption and decryption as
 * well as key generation and parameter handling for all public-key cryptosystems.
 * @requires config
 * @requires crypto/public_key
 * @requires crypto/cipher
 * @requires crypto/hash
 * @requires crypto/random
 * @requires type/kdf_params
 * @requires type/byte_array
 * @requires type/enum
 * @requires type/oid
 * @requires enums
 * @requires util
 * @module crypto/crypto
 */

import publicKey from './public_key';
import * as cipher from './cipher';
import { getRandomBytes } from './random';
import config from '../config';
import KDFParams from '../type/kdf_params';
import ByteArray from '../type/byte_array';
import { SymAlgoEnum, AEADEnum } from '../type/enum';
import enums from '../enums';
import util from '../util';
import OID from '../type/oid';
import { Curve } from './public_key/elliptic/curves';
import CMAC from "./cmac";
import crypto from "./";
import cmac from "./cmac";

/**
 * Encrypts data using specified algorithm and public key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.1|RFC 4880 9.1} for public key algorithms.
 * @param {module:enums.publicKey}    algo          Public key algorithm
 * @param {Object}                    publicParams  Algorithm-specific public key parameters
 * @param {Object}                    privateParams Algorithm-specific private key parameters
 * @param {Uint8Array}                data          Data to be encrypted
 * @param {Uint8Array}                fingerprint   Recipient fingerprint
 * @returns {Object}                                Encrypted session key parameters
 * @async
 */
export async function publicKeyEncrypt(algo, publicParams, privateParams, data, fingerprint) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const { n, e } = publicParams;
      const c = await publicKey.rsa.encrypt(data, n, e);
      return { c };
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      return publicKey.elgamal.encrypt(data, p, g, y);
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicParams;
      const { publicKey: V, wrappedKey: C } = await publicKey.elliptic.ecdh.encrypt(
        oid, kdfParams, data, Q, fingerprint);
      return { V, C: new ByteArray(C) };
    }
    case enums.publicKey.aead: {
      if (!privateParams) {
        throw new Error('Cannot encrypt with symmetric key missing private parameters');
      }
      const { cipher: algo } = publicParams;
      const algoName = algo.getName();
      const { keyMaterial } = privateParams;
      const aeadMode = enums.read(enums.aead, config.aeadMode);
      const mode = crypto[aeadMode];
      const { ivLength } = mode;
      const iv = await getRandomBytes(ivLength);
      const modeInstance = await mode(algoName, keyMaterial);
      const c = await modeInstance.encrypt(data, iv, new Uint8Array());
      return { aeadMode: new AEADEnum(aeadMode), iv, c: new ByteArray(c) };
    }
    default:
      return [];
  }
}

/**
 * Decrypts data using specified algorithm and private key parameters.
 * See {@link https://tools.ietf.org/html/rfc4880#section-5.5.3|RFC 4880 5.5.3}
 * @param {module:enums.publicKey}        algo              Public key algorithm
 * @param {Object}                        publicKeyParams   Algorithm-specific public key parameters
 * @param {Object}                        privateKeyParams  Algorithm-specific private key parameters
 * @param {Object}                        sessionKeyParams  Encrypted session key parameters
 * @param {Uint8Array}                    fingerprint       Recipient fingerprint
 * @returns {Uint8Array}                                    Decrypted data
 * @async
 */
export async function publicKeyDecrypt(algo, publicKeyParams, privateKeyParams, sessionKeyParams, fingerprint) {
  switch (algo) {
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaEncrypt: {
      const { c } = sessionKeyParams;
      const { n, e } = publicKeyParams;
      const { d, p, q, u } = privateKeyParams;
      return publicKey.rsa.decrypt(c, n, e, d, p, q, u);
    }
    case enums.publicKey.elgamal: {
      const { c1, c2 } = sessionKeyParams;
      const p = publicKeyParams.p;
      const x = privateKeyParams.x;
      return publicKey.elgamal.decrypt(c1, c2, p, x);
    }
    case enums.publicKey.ecdh: {
      const { oid, Q, kdfParams } = publicKeyParams;
      const { d } = privateKeyParams;
      const { V, C } = sessionKeyParams;
      return publicKey.elliptic.ecdh.decrypt(
        oid, kdfParams, V, C.data, Q, d, fingerprint);
    }
    case enums.publicKey.aead: {
      const { cipher: algo } = publicKeyParams;
      const algoName = algo.getName();
      const { keyMaterial } = privateKeyParams;

      const { aeadMode, iv, c } = sessionKeyParams;

      const mode = crypto[aeadMode.getName()];
      const modeInstance = await mode(algoName, keyMaterial);
      return modeInstance.decrypt(c.data, iv, new Uint8Array());
    }
    default:
      throw new Error('Invalid public key encryption algorithm.');
  }
}

/**
 * Parse public key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo               The key algorithm
 * @param {Uint8Array}             bytes              The key material to parse
 * @returns {{ read: Number, publicParams: Object }}  Number of read bytes plus key parameters referenced by name
 */
export function parsePublicKeyParams(algo, bytes) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const n = util.readMPI(bytes.subarray(read)); read += n.length + 2;
      const e = util.readMPI(bytes.subarray(read)); read += e.length + 2;
      return { read, publicParams: { n, e } };
    }
    case enums.publicKey.dsa: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, q, g, y } };
    }
    case enums.publicKey.elgamal: {
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const g = util.readMPI(bytes.subarray(read)); read += g.length + 2;
      const y = util.readMPI(bytes.subarray(read)); read += y.length + 2;
      return { read, publicParams: { p, g, y } };
    }
    case enums.publicKey.ecdsa: {
      const oid = new OID(); read += oid.read(bytes);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.eddsa: {
      const oid = new OID(); read += oid.read(bytes);
      let Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      Q = util.padToLength(Q, 33);
      return { read: read, publicParams: { oid, Q } };
    }
    case enums.publicKey.ecdh: {
      const oid = new OID(); read += oid.read(bytes);
      const Q = util.readMPI(bytes.subarray(read)); read += Q.length + 2;
      const kdfParams = new KDFParams(); read += kdfParams.read(bytes.subarray(read));
      return { read: read, publicParams: { oid, Q, kdfParams } };
    }
    case enums.publicKey.cmac:
    case enums.publicKey.aead: {
      const algo = new SymAlgoEnum(); read += algo.read(bytes);
      const cmacLength = CMAC.blockLength;
      const mac = bytes.subarray(read, read + cmacLength); read += cmacLength;
      return { read: read, publicParams: { cipher: algo, mac } };
    }
    default:
      throw new Error('Invalid public key encryption algorithm.');
  }
}

/**
 * Parse private key material in binary form to get the key parameters
 * @param {module:enums.publicKey} algo               The key algorithm
 * @param {Uint8Array}             bytes              The key material to parse
 * @param {Object}                 publicParams       (ECC and symmetric only) public params, needed to format some private params
 * @returns {{ read: Number, privateParams: Object }} Number of read bytes plus the key parameters referenced by name
 */
export function parsePrivateKeyParams(algo, bytes, publicParams) {
  let read = 0;
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      const p = util.readMPI(bytes.subarray(read)); read += p.length + 2;
      const q = util.readMPI(bytes.subarray(read)); read += q.length + 2;
      const u = util.readMPI(bytes.subarray(read)); read += u.length + 2;
      return { read, privateParams: { d, p, q, u } };
    }
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal: {
      const x = util.readMPI(bytes.subarray(read)); read += x.length + 2;
      return { read, privateParams: { x } };
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const curve = new Curve(publicParams.oid);
      let d = util.readMPI(bytes.subarray(read)); read += d.length + 2;
      d = util.padToLength(d, curve.payloadSize);
      return { read, privateParams: { d } };
    }
    case enums.publicKey.eddsa: {
      let seed = util.readMPI(bytes.subarray(read)); read += seed.length + 2;
      seed = util.padToLength(seed, 32);
      return { read, privateParams: { seed } };
    }
    case enums.publicKey.cmac:
    case enums.publicKey.aead: {
      const { cipher: algo } = publicParams;
      const algoName = algo.getName();
      const keySize = cipher[algoName].keySize;
      const keyMaterial = bytes.subarray(read, read + keySize); read += keySize;
      return { read, privateParams: { keyMaterial } };
    }
    default:
      throw new Error('Invalid public key encryption algorithm.');
  }
}

/** Returns the types comprising the encrypted session key of an algorithm
 * @param {module:enums.publicKey} algo   The key algorithm
 * @param {Uint8Array}             bytes  The key material to parse
 * @returns {Object}                      The session key parameters referenced by name
 */
export function parseEncSessionKeyParams(algo, bytes) {
  let read = 0;
  switch (algo) {
    //   Algorithm-Specific Fields for RSA encrypted session keys:
    //       - MPI of RSA encrypted value m**e mod n.
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign: {
      const c = util.readMPI(bytes.subarray(read));
      return { c };
    }

    //   Algorithm-Specific Fields for Elgamal encrypted session keys:
    //       - MPI of Elgamal value g**k mod p
    //       - MPI of Elgamal value m * y**k mod p
    case enums.publicKey.elgamal: {
      const c1 = util.readMPI(bytes.subarray(read)); read += c1.length + 2;
      const c2 = util.readMPI(bytes.subarray(read));
      return { c1, c2 };
    }
    //   Algorithm-Specific Fields for ECDH encrypted session keys:
    //       - MPI containing the ephemeral key used to establish the shared secret
    //       - ECDH Symmetric Key
    case enums.publicKey.ecdh: {
      const V = util.readMPI(bytes.subarray(read)); read += V.length + 2;
      const C = new ByteArray(); C.read(bytes.subarray(read));
      return { V, C };
    }
    //   Algorithm-Specific Fields for symmetric AEAD encryption:
    //       - AEAD algorithm
    //       - Starting initialization vector
    //       - Symmetric key encryption of "m" dependent on cipher and AEAD mode prefixed with a one-octet length
    //       - An authentication tag generated by the AEAD mode.
    case enums.publicKey.aead: {
      const aeadMode = new AEADEnum(); read += aeadMode.read(bytes.subarray(read));
      const mode = crypto[aeadMode.getName()];
      const { tagLength, ivLength } = mode;

      const iv = bytes.subarray(read, read + ivLength); read += ivLength;
      const c = new ByteArray(); read += c.read(bytes.subarray(read));
      const t = bytes.subarray(read, read + tagLength);

      return { aeadMode, iv, c, t };
    }
    default:
      throw new Error('Invalid public key encryption algorithm.');
  }
}

/**
 * Convert params to MPI and serializes them in the proper order
 * @param {module:enums.publicKey}  algo    The public key algorithm
 * @param {Object}                  params  The key parameters indexed by name
 * @returns {Uint8Array}                    The array containing the MPIs
 */
export function serializeParams(algo, params) {
  let orderedParams;
  switch (algo) {
    case enums.publicKey.cmac:
    case enums.publicKey.aead: {
      orderedParams = Object.keys(params).map(name => {
        const param = params[name];
        return util.isUint8Array(param) ? param : param.write();
      });
      break;
    }
    default:
      orderedParams = Object.keys(params).map(name => {
        const param = params[name];
        return util.isUint8Array(param) ? util.uint8ArrayToMpi(param) : param.write();
      });
  }
  return util.concatUint8Array(orderedParams);
}

/**
 * Generate algorithm-specific key parameters
 * @param {module:enums.publicKey}  algo                          The public key algorithm
 * @param {Integer}                 bits                          Bit length for RSA keys
 * @param {module:type/oid}         oid                           Object identifier for ECC keys
 * @param {module:enums.symmetric}  symmetric                     Symmetric algorithm
 * @param {module:enums.packet}     tag                           (only for symmetric algorithms) tag of packet where key material will be stored
 * @param {Integer}                 version                       (only for symmetric algorithms) version of packet where key material will be stored
 * @returns {{ publicParams: {Object}, privateParams: {Object} }} The parameters referenced by name
 * @async
 */
export async function generateParams(algo, bits, oid, symmetric, tag, version) {
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      return publicKey.rsa.generate(bits, 65537).then(({ n, e, d, p, q, u }) => ({
        privateParams: { d, p, q, u },
        publicParams: { n, e }
      }));
    }
    case enums.publicKey.ecdsa:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { d: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.eddsa:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret }) => ({
        privateParams: { seed: secret },
        publicParams: { oid: new OID(oid), Q }
      }));
    case enums.publicKey.ecdh:
      return publicKey.elliptic.generate(oid).then(({ oid, Q, secret, hash, cipher }) => ({
        privateParams: { d: secret },
        publicParams: {
          oid: new OID(oid),
          Q,
          kdfParams: new KDFParams({ hash, cipher })
        }
      }));
    case enums.publicKey.cmac:
    case enums.publicKey.aead: {
      const keyMaterial = await generateSessionKey(symmetric);
      const algo = new SymAlgoEnum(symmetric);
      const cmac = await CMAC(keyMaterial);
      const mac = await cmac(new Uint8Array([tag, version, algo.write()]));

      return {
        privateParams: { keyMaterial },
        publicParams: {
          cipher: algo,
          mac
        }
      };
    }
    case enums.publicKey.dsa:
    case enums.publicKey.elgamal:
      throw new Error('Unsupported algorithm for key generation.');
    default:
      throw new Error('Invalid public key algorithm.');
  }
}

/**
 * Validate algorithm-specific key parameters
 * @param {module:enums.publicKey}  algo          The public key algorithm
 * @param {Object}                  publicParams  Algorithm-specific public key parameters
 * @param {Object}                  privateParams Algorithm-specific private key parameters
 * @param {module:enums.packet}     tag           (only for symmetric algorithms) tag of packet where key material will be stored
 * @param {Integer}                 version       (only for symmetric algorithms) version of packet where key material will be stored
 * @returns {Promise<Boolean>}                    Whether the parameters are valid
 * @async
 */
export async function validateParams(algo, publicParams, privateParams, tag, version) {
  if (!publicParams || !privateParams) {
    throw new Error('Missing key parameters');
  }
  switch (algo) {
    case enums.publicKey.rsaEncrypt:
    case enums.publicKey.rsaEncryptSign:
    case enums.publicKey.rsaSign: {
      const { n, e } = publicParams;
      const { d, p, q, u } = privateParams;
      return publicKey.rsa.validateParams(n, e, d, p, q, u);
    }
    case enums.publicKey.dsa: {
      const { p, q, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.dsa.validateParams(p, q, g, y, x);
    }
    case enums.publicKey.elgamal: {
      const { p, g, y } = publicParams;
      const { x } = privateParams;
      return publicKey.elgamal.validateParams(p, g, y, x);
    }
    case enums.publicKey.ecdsa:
    case enums.publicKey.ecdh: {
      const algoModule = publicKey.elliptic[enums.read(enums.publicKey, algo)];
      const { oid, Q } = publicParams;
      const { d } = privateParams;
      return algoModule.validateParams(oid, Q, d);
    }
    case enums.publicKey.eddsa: {
      const { oid, Q } = publicParams;
      const { seed } = privateParams;
      return publicKey.elliptic.eddsa.validateParams(oid, Q, seed);
    }
    case enums.publicKey.cmac:
    case enums.publicKey.aead: {
      const { cipher: algo, mac } = publicParams;
      const algoName = algo.getName();
      const { keyMaterial } = privateParams;
      const keySize = cipher[algoName].keySize;
      const cmac = await CMAC(keyMaterial);
      return keySize === keyMaterial.length &&
        util.equalsUint8Array(mac, await cmac(new Uint8Array([tag, version, algo.write()])));
    }
    default:
      throw new Error('Invalid public key algorithm.');
  }
}

/**
 * Generates a random byte prefix for the specified algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric}  algo  Symmetric encryption algorithm
 * @returns {Uint8Array}                  Random bytes with length equal to the block size of the cipher, plus the last two bytes repeated.
 * @async
 */
export async function getPrefixRandom(algo) {
  const prefixrandom = await getRandomBytes(cipher[algo].blockSize);
  const repeat = new Uint8Array([prefixrandom[prefixrandom.length - 2], prefixrandom[prefixrandom.length - 1]]);
  return util.concat([prefixrandom, repeat]);
}

/**
 * Generating a session key for the specified symmetric algorithm
 * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
 * @param {module:enums.symmetric}  algo  Symmetric encryption algorithm
 * @returns {Uint8Array}                  Random bytes as a string to be used as a key
 * @async
 */
export function generateSessionKey(algo) {
  return getRandomBytes(cipher[algo].keySize);
}
