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

import { readToEnd as streamReadToEnd, clone as streamClone } from '@openpgp/web-stream-tools';
import { cipherMode, getCipherParams } from '../crypto';
import enums from '../enums';
import util from '../util';
import defaultConfig from '../config';

import LiteralDataPacket from './literal_data';
import CompressedDataPacket from './compressed_data';
import OnePassSignaturePacket from './one_pass_signature';
import SignaturePacket from './signature';
import PacketList from './packetlist';

// A SE packet can contain the following packet types
const allowedPackets = /*#__PURE__*/ util.constructAllowedPackets([
  LiteralDataPacket,
  CompressedDataPacket,
  OnePassSignaturePacket,
  SignaturePacket
]);

/**
 * Implementation of the Symmetrically Encrypted Data Packet (Tag 9)
 *
 * {@link https://tools.ietf.org/html/rfc4880#section-5.7|RFC4880 5.7}:
 * The Symmetrically Encrypted Data packet contains data encrypted with a
 * symmetric-key algorithm. When it has been decrypted, it contains other
 * packets (usually a literal data packet or compressed data packet, but in
 * theory other Symmetrically Encrypted Data packets or sequences of packets
 * that form whole OpenPGP messages).
 */
class SymmetricallyEncryptedDataPacket {
  static get tag() {
    return enums.packet.symmetricallyEncryptedData;
  }

  constructor() {
    /**
     * Encrypted secret-key data
     */
    this.encrypted = null;
    /**
     * Decrypted packets contained within.
     * @type {PacketList}
     */
    this.packets = null;
  }

  read(bytes) {
    this.encrypted = bytes;
  }

  write() {
    return this.encrypted;
  }

  /**
   * Decrypt the symmetrically-encrypted packet data
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} sessionKeyAlgorithm - Symmetric key algorithm to use
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config

   * @throws {Error} if decryption was not successful
   * @async
   */
  async decrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    // If MDC errors are not being ignored, all missing MDC packets in symmetrically encrypted data should throw an error
    if (!config.allowUnauthenticatedMessages) {
      throw new Error('Message is not authenticated.');
    }

    const { blockSize } = getCipherParams(sessionKeyAlgorithm);
    const encrypted = await streamReadToEnd(streamClone(this.encrypted));
    const decrypted = await cipherMode.cfb.decrypt(sessionKeyAlgorithm, key,
      encrypted.subarray(blockSize + 2),
      encrypted.subarray(2, blockSize + 2)
    );

    // Decrypting a Symmetrically Encrypted Data packet MUST yield a valid OpenPGP Message.
    // But due to the lack of authentication over the decrypted data,
    // we do not run any grammarValidator, to avoid enabling a decryption oracle
    // (plus, there is probably a higher chance that these messages have an expected structure).
    this.packets = await PacketList.fromBinary(decrypted, allowedPackets, config);
  }

  /**
   * Encrypt the symmetrically-encrypted packet data
   * See {@link https://tools.ietf.org/html/rfc4880#section-9.2|RFC 4880 9.2} for algorithms.
   * @param {module:enums.symmetric} sessionKeyAlgorithm - Symmetric key algorithm to use
   * @param {Uint8Array} key - The key of cipher blocksize length to be used
   * @param {Object} [config] - Full configuration, defaults to openpgp.config
   * @throws {Error} if encryption was not successful
   * @async
   */
  async encrypt(sessionKeyAlgorithm, key, config = defaultConfig) {
    const data = this.packets.write();
    const { blockSize } = getCipherParams(sessionKeyAlgorithm);

    const prefix = await cipherMode.cfb.getPrefixRandom(sessionKeyAlgorithm);
    const FRE = await cipherMode.cfb.encrypt(sessionKeyAlgorithm, key, prefix, new Uint8Array(blockSize), config);
    const ciphertext = await cipherMode.cfb.encrypt(sessionKeyAlgorithm, key, data, FRE.subarray(2), config);
    this.encrypted = util.concat([FRE, ciphertext]);
  }
}

export default SymmetricallyEncryptedDataPacket;
