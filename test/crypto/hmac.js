const calculateHmac = require('../../src/crypto/hmac');
const enums = require('../../src/enums');
const util = require('../../src/util');
const chai = require('chai');
chai.use(require('chai-as-promised'));

const expect = chai.expect;

function testHmac() {
  it('Passes some examples', async function() {
    const vectors = [
      {
        algo: enums.hash.sha1,
        key: Uint8Array.from('key'),
        data: Uint8Array.from('The quick brown fox jumps over the lazy dog'),
        expected: Uint8Array.from([
          0x80, 0x07, 0x07, 0x13, 0x46, 0x3e, 0x77, 0x49,
          0xb9, 0x0c, 0x2d, 0xc2, 0x49, 0x11, 0xe2, 0x75
        ])
      },
      {
        algo: enums.hash.sha256,
        key: Uint8Array.from('key'),
        data: Uint8Array.from('The quick brown fox jumps over the lazy dog'),
        expected: Uint8Array.from([
          0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
          0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
          0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
          0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
        ])
      }
    ];

    await Promise.all(vectors.map(async vec => {
      const res = await calculateHmac(vec.algo, vec.key, vec.data);
      expect(util.equalsUint8Array(res, vec.expected));
    }));
  });
}

module.exports = () => describe('HMAC reimplementation', function () {
  describe('Examples', function() {
    testHmac();
  });
});
