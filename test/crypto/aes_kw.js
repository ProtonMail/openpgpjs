import { expect } from 'chai';

import * as aesKW from '../../src/crypto/aes_kw.js';
import util from '../../src/util.js';
import enums from '../../src/enums.js';

export default () => describe('AES Key Wrap and Unwrap', function () {
  const test_vectors = [
    [
      '128 bits of Key Data with a 128-bit KEK',
      enums.symmetric.aes128,
      '000102030405060708090A0B0C0D0E0F',
      '00112233445566778899AABBCCDDEEFF',
      '1FA68B0A8112B447 AEF34BD8FB5A7B82 9D3E862371D2CFE5'
    ],
    [
      '128 bits of Key Data with a 192-bit KEK',
      enums.symmetric.aes192,
      '000102030405060708090A0B0C0D0E0F1011121314151617',
      '00112233445566778899AABBCCDDEEFF',
      '96778B25AE6CA435 F92B5B97C050AED2 468AB8A17AD84E5D'
    ],
    [
      '128 bits of Key Data with a 256-bit KEK',
      enums.symmetric.aes256,
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      '00112233445566778899AABBCCDDEEFF',
      '64E8C3F9CE0F5BA2 63E9777905818A2A 93C8191E7D6E8AE7'
    ],
    [
      '192 bits of Key Data with a 192-bit KEK',
      enums.symmetric.aes192,
      '000102030405060708090A0B0C0D0E0F1011121314151617',
      '00112233445566778899AABBCCDDEEFF0001020304050607',
      '031D33264E15D332 68F24EC260743EDC E1C6C7DDEE725A93 6BA814915C6762D2'
    ],
    [
      '192 bits of Key Data with a 256-bit KEK',
      enums.symmetric.aes256,
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      '00112233445566778899AABBCCDDEEFF0001020304050607',
      'A8F9BC1612C68B3F F6E6F4FBE30E71E4 769C8B80A32CB895 8CD5D17D6B254DA1'
    ],
    [
      '256 bits of Key Data with a 256-bit KEK',
      enums.symmetric.aes256,
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
      '00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F',
      '28C9F404C4B810F4 CBCCB35CFB87F826 3F5786E2D80ED326 CBC7F0E71A99F43B FB988B9B7A02DD21'
    ]
  ];

  test_vectors.forEach(function(test) {
    it(test[0], async function() {
      const algo = test[1];
      const kek = util.hexToUint8Array(test[2]);
      const input = test[3].replace(/\s/g, '');
      const input_bin = util.hexToUint8Array(input);
      const output = test[4].replace(/\s/g, '');
      const output_bin = util.hexToUint8Array(output);
      expect(util.uint8ArrayToHex(await aesKW.wrap(algo, kek, input_bin)).toUpperCase()).to.equal(output);
      expect(util.uint8ArrayToHex(await aesKW.unwrap(algo, kek, output_bin)).toUpperCase()).to.equal(input);
    });
  });
});
