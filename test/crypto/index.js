import testBigInteger from './biginteger';
import testCipher from './cipher';
import testHash from './hash';
import testCrypto from './crypto';
import testElliptic from './elliptic';
import testBrainpoolRFC7027 from './brainpool_rfc7027';
import testECDH from './ecdh';
import testPKCS5 from './pkcs5';
import testAESKW from './aes_kw';
import testHKDF from './hkdf';
import testHMAC from './hmac';
import testGCM from './gcm';
import testEAX from './eax';
import testOCB from './ocb';
import testRSA from './rsa';
import testValidate from './validate';
import testPQC from './postQuantum';

export default () => describe('Crypto', function () {
  testBigInteger();
  testCipher();
  testHash();
  testCrypto();
  testElliptic();
  testBrainpoolRFC7027();
  testECDH();
  testPKCS5();
  testAESKW();
  testHKDF();
  testHMAC();
  testGCM();
  testEAX();
  testOCB();
  testRSA();
  testValidate();
  testPQC();
});
