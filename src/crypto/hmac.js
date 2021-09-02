/**
 * @fileoverview This module implements an abstracted interface over
 * HMAC implementation from asmcrypto.js
 * @module crypto/hmac
 * @private
 */

import enums from '../enums';
import util from '../util';
import hash from './hash';

/**
 * Creats an HMAC object for data authentication
 * @param {module:enums.hash} algo - The hash algorithm to be used in the hmac
 * @param Uint8Array key - The key for the hmac computation
 */
export default function calculateHmac(algo, key, data) {
  switch (algo) {
    case enums.hash.sha1:
    case enums.hash.sha256:
    case enums.hash.sha512:
      return hmac(algo, key, data);
    default:
      throw new Error('Unsupported hash algorithm.');
  }
}

async function hmac(algo, key, data) {
  const blockSize = hash.getBlockSize(algo);

  const opad = new Uint8Array(blockSize);
  opad.fill(0x5c);
  xorInplace(opad, key);
  const ipad = new Uint8Array(blockSize);
  ipad.fill(0x36);
  xorInplace(ipad, key);

  const inner_payload = util.concatUint8Array([ipad, data]);
  const inner_hash = await hash.digest(algo, inner_payload);
  const payload = util.concatUint8Array([opad, inner_hash]);
  return hash.digest(algo, payload);
}

function xorInplace(a, b) {
  for (let i = 0; i < a.length; i++) {
    a[i] ^= b[i] || 0;
  }
}
