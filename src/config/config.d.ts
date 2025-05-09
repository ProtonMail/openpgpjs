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

/**
 * Global configuration values.
 */

import enums from '../enums';

export interface Config {
  preferredHashAlgorithm: enums.hash;
  preferredSymmetricAlgorithm: enums.symmetric;
  preferredCompressionAlgorithm: enums.compression;
  showVersion: boolean;
  showComment: boolean;
  aeadProtect: boolean;
  ignoreSEIPDv2FeatureFlag: boolean;
  parseAEADEncryptedV4KeysAsLegacy: boolean;
  allowUnauthenticatedMessages: boolean;
  allowUnauthenticatedStream: boolean;
  allowForwardedMessages: boolean;
  minRSABits: number;
  passwordCollisionCheck: boolean;
  ignoreUnsupportedPackets: boolean;
  ignoreMalformedPackets: boolean;
  additionalAllowedPackets: Array<{ new(): any }>;
  versionString: string;
  commentString: string;
  allowInsecureDecryptionWithSigningKeys: boolean;
  allowInsecureVerificationWithReformattedKeys: boolean;
  allowMissingKeyFlags: boolean;
  constantTimePKCS1Decryption: boolean;
  constantTimePKCS1DecryptionSupportedSymmetricAlgorithms: Set<enums.symmetric>;
  v6Keys: boolean;
  enableParsingV5Entities: boolean;
  preferredAEADAlgorithm: enums.aead;
  aeadChunkSizeByte: number;
  s2kType: enums.s2k.iterated | enums.s2k.argon2;
  s2kIterationCountByte: number;
  s2kArgon2Params: { passes: number, parallelism: number; memoryExponent: number; };
  maxUserIDLength: number;
  knownNotations: string[];
  nonDeterministicSignaturesViaNotation: boolean;
  useEllipticFallback: boolean;
  rejectHashAlgorithms: Set<enums.hash>;
  rejectMessageHashAlgorithms: Set<enums.hash>;
  rejectPublicKeyAlgorithms: Set<enums.publicKey>;
  rejectCurves: Set<enums.curve>;
}

declare const config: Config;
export default config;
