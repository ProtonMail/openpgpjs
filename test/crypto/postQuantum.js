import { use as chaiUse, expect } from 'chai';
import chaiAsPromised from 'chai-as-promised'; // eslint-disable-line import/newline-after-import
chaiUse(chaiAsPromised);

import openpgp from '../initOpenpgp.js';
import { generateParams, publicKeyEncrypt, publicKeyDecrypt } from '../../src/crypto/crypto.js';

export default () => describe('PQC - Kyber + X25519', function () {
  it('Generate/encaps/decaps', async function () {
    const sessionKey = { data: new Uint8Array(16).fill(1), algorithm: 'aes128' };

    const { privateParams, publicParams } = await generateParams(openpgp.enums.publicKey.pqc_mlkem_x25519);
    const encryptedSessionKeyParams = await publicKeyEncrypt(openpgp.enums.publicKey.pqc_mlkem_x25519, undefined, publicParams, null, sessionKey.data);
    const decryptedSessionKey = await publicKeyDecrypt(openpgp.enums.publicKey.pqc_mlkem_x25519, publicParams, privateParams, encryptedSessionKeyParams);
    expect(decryptedSessionKey).to.deep.equal(sessionKey.data);
  });
});
