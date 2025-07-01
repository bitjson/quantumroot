import { test, expect } from 'bun:test';
import { instantiateLmOts, lmOtsSha256n32w4, lmOtsSha256n32w8 } from './lm-ots';
import {
  assertSuccess,
  binToHex,
  createCompilerBch,
  createVirtualMachineBch2026,
  debugCashAssembly,
  decodeTransaction,
  decodeTransactionOutputs,
  encodeTransaction,
  encodeTransactionOutputs,
  evaluateCashAssembly,
  flattenBinArray,
  hexToBin,
  importWalletTemplate,
  numberToBinUint16BE,
  numberToBinUint32BE,
  sha256,
  sortObjectKeys,
  stringify,
  vmNumberToBigInt,
  walletTemplateToCompilerConfiguration,
} from '@bitauth/libauth';
import fc from 'fast-check';
import templateJson from '../quantumroot-schnorr-lm-ots-vault.json';
import staticVector from './static-vector.json';

test('LM-OTS coefficient extraction', () => {
  const bytes4 = Uint8Array.from([0xab, 0xcd]);
  expect(lmOtsSha256n32w4.coef(bytes4, 0)).toBe(0x0a);
  expect(lmOtsSha256n32w4.coef(bytes4, 1)).toBe(0x0b);
  expect(lmOtsSha256n32w4.coef(bytes4, 2)).toBe(0x0c);
  expect(lmOtsSha256n32w4.coef(bytes4, 3)).toBe(0x0d);

  const bytes8 = Uint8Array.from([0xcd, 0xef]);
  expect(lmOtsSha256n32w8.coef(bytes8, 0)).toBe(0xcd);
  expect(lmOtsSha256n32w8.coef(bytes8, 1)).toBe(0xef);
});

test('checksum: published vector values', () => {
  const q4 = hexToBin(
    '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a236'
  );
  expect(lmOtsSha256n32w4.checksum(q4)).toBe(7520);
  const q8 = hexToBin(
    'ea1d9f55ef8b75d1b5e119f4626ed5a6b6d6204f213b2cdc2a9aed4659117e6e'
  );
  expect(lmOtsSha256n32w8.checksum(q8)).toBe(3979);
});

const lmOtsSha256n32w4Tracing = () => {
  let trace: { i: number; input: string; hash: string }[] = [];
  const traceAndHash = (input: Uint8Array) => {
    const out = sha256.hash(input);
    const hash = binToHex(out);
    trace.push({ i: trace.length, hash, input: binToHex(input) });
    return out;
  };
  const read = () => trace;
  const clear = () => (trace = []);
  const instance = instantiateLmOts({ hash: traceAndHash, baseW: 4 });
  clear();
  return { clear, instance, read };
};

test('Produce w=4 test vector with traces for CashAssembly implementation', () => {
  const { clear, instance, read } = lmOtsSha256n32w4Tracing();
  const seed = hexToBin(staticVector.seed);
  const I = hexToBin(staticVector.I);
  const q = staticVector.q;
  const K = hexToBin(staticVector.K);
  const C = hexToBin(staticVector.C);
  const expectedPreImage = hexToBin(
    'd08fabd4a2091ff0a8cb4ed834e745340000000081812773ae45f3d3a711b3067d51f539eb7c1e9e6a0ea44893d4c73ff926c14a691d6578616d706c65'
  );
  const expectedQ = hexToBin(
    '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a236'
  );
  const expectedChecksum = 7520;
  const expectedEncodedMessageHash = hexToBin(
    '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a2361d60'
  );
  const sk = instance.generatePrivateKey(seed, I, q);
  const read1 = read();
  expect(read1.length).toEqual(67);
  expect(read1[0]).toEqual({
    i: 0,
    hash: 'f84c9039770402b34f9ede799d8c42bd5a870d5fada473a76d268b3d0549f3d6',
    input:
      'd08fabd4a2091ff0a8cb4ed834e74534000000000000ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  });
  expect(read1[66]).toEqual({
    i: 66,
    hash: '8ed107064a81ef532dff8842e14b6252064a678b6ee291166bdc916df81e87fe',
    input:
      'd08fabd4a2091ff0a8cb4ed834e74534000000000042ff000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
  });
  clear();
  const pk = instance.derivePublicKey(sk, I, q);
  const read2 = read();
  expect(read2.length).toEqual(1006);
  Bun.write('./w4-static-vector-public-key-hashes.json', stringify(read2));
  expect(read2[0]).toEqual({
    hash: '0f1932ab65fa1948bba0c8b888b5a79bfad8dca709c7cccfb4e5c94f291fc4a4',
    i: 0,
    input:
      'd08fabd4a2091ff0a8cb4ed834e7453400000000000000f84c9039770402b34f9ede799d8c42bd5a870d5fada473a76d268b3d0549f3d6',
  });
  expect(pk).toEqual(K);
  const message = hexToBin(staticVector.message);
  clear();
  const sign = instance.sign(message, sk, I, q, C);
  const { signature: sig, Q, preImage, encodedMessageHash, checksum } = sign;
  expect(preImage).toEqual(expectedPreImage);
  expect(Q).toEqual(expectedQ);
  expect(checksum).toEqual(expectedChecksum);
  expect(encodedMessageHash).toEqual(expectedEncodedMessageHash);
  const read3 = read();
  expect(read3.length).toEqual(511);
  Bun.write('./w4-static-vector-signing-hashes.json', stringify(read3));
  expect(read3[0]).toEqual({
    hash: '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a236',
    i: 0,
    input:
      'd08fabd4a2091ff0a8cb4ed834e745340000000081812773ae45f3d3a711b3067d51f539eb7c1e9e6a0ea44893d4c73ff926c14a691d6578616d706c65',
  });
  expect(read3[1]).toEqual({
    hash: '0f1932ab65fa1948bba0c8b888b5a79bfad8dca709c7cccfb4e5c94f291fc4a4',
    i: 1,
    input:
      'd08fabd4a2091ff0a8cb4ed834e7453400000000000000f84c9039770402b34f9ede799d8c42bd5a870d5fada473a76d268b3d0549f3d6',
  });
  expect(read3[2]).toEqual({
    hash: '7a082c17ce058eb3e4048f772b8c3137d2a4ea32f1dcedbcaf03d0b949b31435',
    i: 2,
    input:
      'd08fabd4a2091ff0a8cb4ed834e74534000000000000010f1932ab65fa1948bba0c8b888b5a79bfad8dca709c7cccfb4e5c94f291fc4a4',
  });
  expect(read3[3]).toEqual({
    hash: '552015bd3e70f7797fafa92d6aa96eeb1d20c5765d8f51853d99e3bfff3c48ce',
    i: 3,
    input:
      'd08fabd4a2091ff0a8cb4ed834e74534000000000000027a082c17ce058eb3e4048f772b8c3137d2a4ea32f1dcedbcaf03d0b949b31435',
  });
  expect(read3[4]).toEqual({
    hash: 'd72360a14a2d18138e27d573061cdafb777c9fe35a2573d30060837438843e82',
    i: 4,
    input:
      'd08fabd4a2091ff0a8cb4ed834e7453400000000000100f558df0d9544266319478324dc59fec0a719dea939639a5fc72e5e56bd8f704e',
  });
  expect(read3[5]).toEqual({
    hash: '993e4d9bdcd5ef0846beba8cbdf46fce20e110aeec44caeab6fecb73d9923923',
    i: 5,
    input:
      'd08fabd4a2091ff0a8cb4ed834e7453400000000000101d72360a14a2d18138e27d573061cdafb777c9fe35a2573d30060837438843e82',
  });
  expect(read3[510]).toEqual({
    hash: 'a071cc56a77e2a7fb28773fa978684353bc9e8f6e9181c70811ea3bc717f87a2',
    i: 510,
    input:
      'd08fabd4a2091ff0a8cb4ed834e7453400000000004205ca7374f2d26642378bbfbc6e7a3058ee37ce76afa9907f28406c0eac60366a77',
  });
  expect(sig.Y[0]).toEqual(
    hexToBin('552015bd3e70f7797fafa92d6aa96eeb1d20c5765d8f51853d99e3bfff3c48ce')
  );
  expect(sig.Y.map(binToHex).join('')).toEqual(staticVector.Y);
  expect(binToHex(flattenBinArray(sk))).toEqual(staticVector.x);
});

test('lmOtsSha256n32w4: reproduces a test vector from trailofbits/lms-go TestOtsSignVerify/LMOTS_SHA256_N32_W4', () => {
  const seed = hexToBin(staticVector.seed);
  const I = hexToBin(staticVector.I);
  const q = staticVector.q;
  const K = hexToBin(staticVector.K);
  const C = hexToBin(staticVector.C);
  const expectedPreImage = hexToBin(
    'd08fabd4a2091ff0a8cb4ed834e745340000000081812773ae45f3d3a711b3067d51f539eb7c1e9e6a0ea44893d4c73ff926c14a691d6578616d706c65'
  );
  const expectedQ = hexToBin(
    '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a236'
  );
  const expectedChecksum = 7520;
  const expectedEncodedMessageHash = hexToBin(
    '326d34253ec0b3e9fa4cf2f708edf471d5d2caeeb1d1b388a4c4476a19d4a2361d60'
  );
  const Y = [
    '552015bd3e70f7797fafa92d6aa96eeb1d20c5765d8f51853d99e3bfff3c48ce',
    '993e4d9bdcd5ef0846beba8cbdf46fce20e110aeec44caeab6fecb73d9923923',
    '1f0f5317f7a783a4429254d6b8907946755b14edbdf5ee5a352020bf38c5373b',
    'a38fd0e67eb7a5276686cfc9fe8cd3e21ba142e88cec65c554dd2778297e3e9c',
    '681f33fa6fca58649432516b1cc82c0b52ac5a0aba7eb5f02430b39c2e9c6805',
    '07a584e201ae89bbbeb2a4463cec235bf16ce7ea4d2b20aa766c1ff8ebc32fcc',
    '9d8647915f53191168079b288e65380350c7b69eca6a332fc69a7575e3fa16f5',
    'a2a623f6f941aeee39972e86356c2974778140d8ab5aed264297f62f950cd068',
    'b95d09e0757a8c7c9c1eefdf036ea8dc31f8dd2a03bbb1007fa15fe3addabd5d',
    '29608c1c19ba2db952d7e97853e9bb4d64d4745ddbe59c7bcce78eaf9a6a6c88',
    '50e63e16fdb447010b01f388bde5f001425f8a7bb974ee6a86f5697708af044b',
    '8d7da70fc8ef0697822fd190120e634a8dd732d83eb5853eb3df54f4fc0e838e',
    '967e9551698d36bf2a037ed1c4ba3270a079aae784845d1112a93ad5e20a60de',
    'd4046fd5d0f67dc933c85bec4baf93c49ba5a460484b5568f26c4ee54cdc11b4',
    '9317d6a1c23ddc4f324ff001718f8906264d49d8900a6a51f42dad42ee9591fc',
    'f743efd1782954dc57600618821aeb7d6b37e59c9dcee0c80d35f4be265a9d30',
    '61899eb7ed3c2ef35287daa2facd233c6a9b491764216411d387851a3c4b2ae6',
    '73922822cdcdc66285dcbbffd2eabe502ffe199654f3cc98fde6b3234add60cf',
    'f9d60271b1959e0d5a92e589124e1070a0c7fa90b6853f028640569c00b26aa7',
    '6ee7d372c4e4c1d5b50576aa17c3d37eb453eadce3756010caef606c77cae015',
    '49ce634ff3da23b5b0567d398ddddffda0267c81b30af912c66ab2bb7f3e378c',
    '6da86a599a2f00bc9dc09cc7dad9940eea4f2e2f82a50755c535e17dff31d091',
    '1f5055d5e09deb52a44f083fa7f2a79ef7f5168a5244b6581f5862817268811c',
    '8a01048d4f74bcb786ac1fa777944951440619bce2d5157d3eedcb086cdd2692',
    '398b92e4f4a23544aa376970cf3b2be9b3693c5a1eddf8c4372c50b5dd03b077',
    'b6fa941d763431f8a96c65d5a8755487b2bc6c20c5b5a5f25f8943c825045fdd',
    'd3273f87f077b53e66e5035671a9f37d97310eb7cb888de9f10c484beee6f1e9',
    '044b0ee22c4004e498eec5566ffbcad1c029f8f6aa768eb8da0045a17f3ccd92',
    '4d30f195fed20aec4c4e2860f13470e796d296e8a0e897289bcf303ab5db4947',
    '487cbc1c54cbdc04505485cb5ebc55cfc0336a62502baa7d8dae2c9f7f2588f2',
    '7c21fe3bdd0b6e92e857be306f5e0e6c77a900a7cd5b86bead3698c12f1ebb4a',
    '183ea47fb42cc8f11857c7a45a9a3ab44682b7bf36674e8b7cfd9ae4b6e0aa49',
    '51b04ed42ac76035b356b7cd92df79f320d36053a401a9d70ea0a6f587142a35',
    'd1a5dcf77c94e3e0f511f13239486b89e3d12ad61195ff048e76a9948b0a178a',
    '91fc9ed81b6f07b14c3488f7c87b986a6d16f63598629fea1c78fefe1f1805a9',
    '7cd27e20b90d4fee642a6d901a6160842e23507a5cd3f8befc98136133e703c1',
    '4e9ed6a20bd138c7e0af9bca340f718fad53f109202ec15c494df621d723c756',
    'd532fea1c4dbd32532e203c9e8bcb4def99138798eff93c8e8b45ec699b6ae4a',
    '40a8d81f8404e2cd7f12b61ccec6e6e815cbd00ad544a3072d2b39fa5de3a351',
    '7266ddcf11f5eae7f75c1ae3429ab8109e148f7742afc6a9a1bc8a5547a5c5ca',
    'c85eac7246a5d4e26440cbf4142f66b91a478b39fca733ce9e59792e21223e4c',
    'b16f3afd9669e45f61fd74309b9f6b13454a05e8a354dc717f1e513f619e2f32',
    '6821622ea6b23738a41959c8c20567656b9290fb153cb5ff65567f28e8a89017',
    'c5754d26dda4e29de97360b1d45afef923f83724ab577585d2389f25b4573151',
    'c24035e7436d13bc432430c0a5403eaa807d71def9ea3ee4243cec5cbac90501',
    'c609bdcaf1c0e458c99dba2c12568ad082778d8e3ba834f28068052ad12d53c0',
    '78ae7996adffa89231389bd023ead59b4718363660a8fc6fa163ac206b052356',
    'f100866801e292af77a81ac1402ebdd7af6ab0b63677a6ea3dee32204b395321',
    'e86b979bdd295a1811b15113efb690e50766f55157b1f35963813e3847f2d900',
    '1b76dfd5bbaddae5a72c91572253705a120f695510cf8127143790f299a124f6',
    '14e489208d5b77f93c9a121092d439f2904ba3771278412815af72804d34e583',
    '4fc4080d41c893759256b4b2bf022bcf74320b97b59d97b86e72ce58f7b07095',
    '28a3fa99acb9f5ec679a68c072b4e797ceea170a9840343cdab294302bbae2f3',
    'dcefc903adf2267210fce3e4a0c0bdcf9f52ad76a9a09fa288c78e0842d0c82c',
    '82b0b93a51ef56bf4dd66aeadf9238f104514f1d714dd3b863089e470ff47479',
    '4b7e6e478d5a0095970e0ab488543569931e16152f6e7ccd83240e06cde70dc3',
    'f244a201e1690f6823b9c3e6989f2c99cb448f079737b0baab4fa2ea24e14913',
    '6db8caedf9d120d93fdf23d218d0d8c29771deb7747b338e95677584c30db9a7',
    'c85f622d29d2fa44c308083166451871e68be0173e48ceafcb35d87a7307c13a',
    'da5be013be6c8b3d294fd6e1db3d1b834305177d1c49dbdd8cabdd61c92feab6',
    '085da31319984c58d9b0be66008ba7a5a33251d4390dffb295cb601f7ecce54c',
    '79e381258d6fae76a9c488a30106e68a9b0aeeaad08ad83f22ce9a70f733f10c',
    'c210a488e17029c4c8f713c481d53ba6a9f69d0df9fc064c36e547bad6c16496',
    '3d31a971262b85e60ad6b0ce8f25b28d91a3d1fb679dca7e8b80bd2ad0f76e76',
    '3b6cf2a4cb8d4a226bfc002e073f6760fb806725c550e97c6d89b15929bf8401',
    '4ef78c09d0e2e6ec8301a3ded2531daf0fe1d863a6fea0ae9e21642e315afccf',
    'a071cc56a77e2a7fb28773fa978684353bc9e8f6e9181c70811ea3bc717f87a2',
  ].map(hexToBin);
  const sk = lmOtsSha256n32w4.generatePrivateKey(seed, I, q);
  const pk = lmOtsSha256n32w4.derivePublicKey(sk, I, q);
  expect(pk).toEqual(K);
  const message = hexToBin(staticVector.message);
  const sign = lmOtsSha256n32w4.sign(message, sk, I, q, C);
  const { signature: sig, Q, preImage, encodedMessageHash, checksum } = sign;
  expect(preImage).toEqual(expectedPreImage);
  expect(Q).toEqual(expectedQ);
  expect(checksum).toEqual(expectedChecksum);
  expect(encodedMessageHash).toEqual(expectedEncodedMessageHash);
  expect(lmOtsSha256n32w4.verify(message, sig, I, q, pk)).toBe(true);
  expect(sig.C).toEqual(C);
  expect(sig.Y[0]).toEqual(Y[0]);
  expect(sig.Y).toEqual(Y);
});
test('lmOtsSha256n32w8: reproduces a test vector from trailofbits/lms-go TestOtsSignVerify/LMOTS_SHA256_N32_W8', () => {
  const seed = hexToBin(staticVector.seed);
  const I = hexToBin(staticVector.I);
  const q = 0;
  const K = hexToBin(
    '2364a1454cd2aa93162b8ad38ec71ece626f1816909899f22ec9acab0b99b51c'
  );
  const C = hexToBin(
    'd0647893f084109c02b4e5aeaaf653e39478cace196ca16709724e664d4446b5'
  );
  const expectedPreImage = hexToBin(
    'd08fabd4a2091ff0a8cb4ed834e74534000000008181d0647893f084109c02b4e5aeaaf653e39478cace196ca16709724e664d4446b56578616d706c65'
  );
  const expectedQ = hexToBin(
    'ea1d9f55ef8b75d1b5e119f4626ed5a6b6d6204f213b2cdc2a9aed4659117e6e'
  );
  const expectedChecksum = 3979;
  const expectedEncodedMessageHash = hexToBin(
    'ea1d9f55ef8b75d1b5e119f4626ed5a6b6d6204f213b2cdc2a9aed4659117e6e0f8b'
  );
  const Y = [
    'ec5b28494853b41af6174bfcf61b6de91235e35fdad319f5c3bc670887d4d027',
    'ff8c1f032a1eb6e0fa4b4b7e33bd86da5b6904f1f998b0a6e15248d64867172d',
    '4e35d7c808f540e6ebc9b3334f5e5b8e523c1d49a59e60dc92c56ae79a3f6bb4',
    'bef60ce2bbd7d2b1cd2ef463b16018720e580b332cefd69a17be43f68b316e82',
    '94a3a56a537617744413b1ce0e653118e36e8ec6403f15d11ca350b4d9a828df',
    'e14fe6110b28c5e6414f475d6e401bb665ebcb95afc091c4887180ae600e5a45',
    '504fbec68a68c9117bbf07f4dcb906b15e7f18e86765a4fe0664c2220dc8b441',
    'f27c66e27505f27352f64514b8b93f8a08eff1555ed146cd68917b897d6bc354',
    '4bfe814753207d0ead87938902c2e8deeabcb33102c2aa13c1f97db8711580d1',
    '67ada235c334da4ba2cd35a0f04e9f7182aa1f2ab3644ca6da690d686f7f93ab',
    '7aa98b564003939f899bfeb81fb0ca3077f1adc3145805b1518ed5f497d3937b',
    '931521170a939f073eb49b7ff4016a1e059369d9f35ac483a4421b64ec34a874',
    '36ce4344a9a7ad03d6baa8b9dbf1183736d739ae6b657ab6649b47d97440e175',
    'efb7b54043bb18aa43e23a869936b11aa4140201e084a0a2c4358fd605346ec6',
    '06b7e3d30d14a69eff9671915117676032f847f643a730ff60816dec891a28a4',
    'c0f98bdebb22447898ff3eaf5142991b3990f987497441c917e38b275771b1ab',
    '8150df036797e3d52941c62c0e8e40658b96c61a09f64a536334a0212aa40209',
    'a4517e477f86dbbf54498d3dbcafcb78cce7077d1cebe0867720eb4f8689e584',
    '5f9117170bce34d0924db76e896cb0987d53faa9e489d4ced9c7928bdf8f1e15',
    '34fef76f033e8cdf8be8f2af87e3b9fe167d5a845650a219a7d34bd11604f011',
    '0dd2f7c070b5076928f26974eac689aa7a496494758e3dc2279cb40262b1b867',
    'f6e832a19b22ccd6fd98bf83511956a6f95a6a6a2e020dacc1b11a7f15e9b4b0',
    'd43798048accaf9e1bfbc43611912ebdb38f46a4e126c21ef73c9872d6632ebb',
    'a0690a0b04e8c1d3e461c65ff3483f99308ea983b51ae5760a2764e8d1ac02d2',
    '239d2862888825327d20fc2538894d272ebb0bd7cb7c58c5fe44ef6786574032',
    '98d0fa95f30002aa686a832781884bb98fb7a9a31d42716a2c1fa593e53c86fb',
    'b751dd12047e1d877a13948aaf0388f1dadaa93ea9777566fdcd74387f740a27',
    '47afe787ced6e0e46505b77985c1ac1521cd8626c12d5f3b47b29209f92f6718',
    'dbfe944412fd177e5932c29a8ab76705a197a9e9431c9b193d069ec89ebaadc1',
    'ac8f6573608cdce9d19b641de39795937403b3c6dc161b6129d6e49445f6a1f1',
    '34647af4dc0f434beab0248bcfafc4ba7179e0e1ca91d63023078c5861b8d199',
    '433e570ffaf3ed17430d588c337ca4cefb07a51f927d081382fe3d6714c1dd83',
    'a9917cc12fd1c9d9de6ce5f66751132fdcabf7324afcb4599ef4c72546a31516',
    '666e77087e2909ea31e302b106867d35f176bd1bbf7977667e081849d7eb8065',
  ].map(hexToBin);
  const sk = lmOtsSha256n32w8.generatePrivateKey(seed, I, q);
  const pk = lmOtsSha256n32w8.derivePublicKey(sk, I, q);
  expect(pk).toEqual(K);
  const message = hexToBin(staticVector.message);
  const sign = lmOtsSha256n32w8.sign(message, sk, I, q, C);
  const { signature: sig, Q, preImage, encodedMessageHash, checksum } = sign;
  expect(preImage).toEqual(expectedPreImage);
  expect(Q).toEqual(expectedQ);
  expect(checksum).toEqual(expectedChecksum);
  expect(encodedMessageHash).toEqual(expectedEncodedMessageHash);
  expect(lmOtsSha256n32w8.verify(message, sig, I, q, pk)).toBe(true);
  expect(sig.C).toEqual(C);
  expect(sig.Y[0]).toEqual(Y[0]);
  expect(sig.Y).toEqual(Y);
});
const thePowers = hexToBin(
  '54686520706f77657273206e6f742064' +
    '656c65676174656420746f2074686520' +
    '556e6974656420537461746573206279' +
    '2074686520436f6e737469747574696f' +
    '6e2c206e6f722070726f686962697465' +
    '6420627920697420746f207468652053' +
    '74617465732c20617265207265736572' +
    '76656420746f20746865205374617465' +
    '7320726573706563746976656c792c20' +
    '6f7220746f207468652070656f706c65' +
    '2e0a'
); // From RFC 8554: `The powers not delegated to the United States by the Constitution nor prohibited by it to the States, are reserved to the States respectively, or to the people..`

test('lmOtsSha256n32w4: Reproduces a test vector from trailofbits/lms-go TestSignKAT1 (LMOTS_SHA256_N32_W4)', () => {
  const seed = hexToBin(
    '558b8966c48ae9cb898b423c83443aae014a72f1b1ab5cc85cf1d892903b5439'
  );
  const I = hexToBin(staticVector.I);
  const q = 5;
  const K = hexToBin(
    '39cdd3ac94d648be37f6c7c1d24479297c26456da70ba9eed8f1ce468bc4f3e1'
  );
  const C = hexToBin(
    '250267df33b626de454a426913d629b0dcaa6ba4c7408c1d38146697086cd8c4'
  );
  const expectedPreImage = hexToBin(
    'd08fabd4a2091ff0a8cb4ed834e74534000000058181250267df33b626de454a426913d629b0dcaa6ba4c7408c1d38146697086cd8c454686520706f77657273206e6f742064656c65676174656420746f2074686520556e69746564205374617465732062792074686520436f6e737469747574696f6e2c206e6f722070726f6869626974656420627920697420746f20746865205374617465732c2061726520726573657276656420746f207468652053746174657320726573706563746976656c792c206f7220746f207468652070656f706c652e0a'
  );
  const expectedQ = hexToBin(
    '968caf6c499c7a3cb2d08a754ba63ccee8f8729e9bbc37914b766bb011bb6ef3'
  );
  const expectedChecksum = 6880;
  const expectedEncodedMessageHash = hexToBin(
    '968caf6c499c7a3cb2d08a754ba63ccee8f8729e9bbc37914b766bb011bb6ef31ae0'
  );
  const Y = [
    '6c041cf8e0d78ce8925e3244fa7d45b8464f69fc1399c457c6618d5b9ca6e022',
    '8577b31a7540f694a2bc3103ad0e3a58ac40775fd1355376394ca86d666f0c9f',
    '0625e14b6a4b7398d1ea89eddd8ca4f40749105d4bae6ce5d774a42cd3da81ed',
    '146c3095be29fd8ec720199d8ffb88b3130b67a6e991be433f02ab9a8219e8ba',
    '496d36d2576e5f2948027d1a5982daa98a428097ae063a399da810173cc057c7',
    '93a04815544643609a9f6506ba31e9e94c55767bd08e1b5d5c49363e87275b22',
    'c67bf10d28143010e3881f7e1f6ad841ade9b0f1c756b99b4739ac9d71dbd570',
    '1e57b93fef1545dadd74749a6a6d5f45a001f45909858fc3c7e9612e2e54285f',
    '0208d231f37d8860cafc9ade328e72d715f0a9e3f83cb91a5e5cf34309acc0df',
    'a48fbeb309d3eee2ccf31cf50f9ef5b01d136394fac1fac7170e98452f1a27d7',
    'd635c9bf516433ca21030ea3e307597d685f68c9d5cc92d9ee66b61a2ced8a4e',
    '0149bb8de9709e832efb3a40d81036357fc334aefb46b172bf3d7bcdfebcc505',
    '53def7507188f5185a951ff5881e0305572eb90ee361b304b064b7e2cfb155f3',
    'bb48803116a2a6b679626f6012f98d143f3a013a0abfd1c0615cf59be90a20ba',
    '7a04cb17e79dbb672b80f0b802e107349d43fbd0566c7747e4756c14336711fa',
    'e54f6404459ec85ca52165e4b63d313873b685a7c1d38d4e87f4beca28eb367b',
    '155ce1f02f021e772d7b476b2e465a77ae2d79028caa904a8f5c8db281bf8ba0',
    '9dffe7d50c6f4bbec369eb86763e761196ab6045af6286b39f86572ca38087fb',
    'dc007531e47fc4fdfc3de772f724c9389fec17e84ac5fc644a1bc69ba639b254',
    '9b2f950654a802ad7121c3ecc52be6e604dcc6557cf60eb4e02ba46c5f01dbb9',
    '8e066ba4f619f216bcc0a35dcf821e74ef90a656774162e8d10bd5173f0fba0f',
    '1f388db25cb47b302b5d3ca58a97abcb40f903f60b4d67f6da4798c28e5107a1',
    'c9db7faaecce88c6486dff57ba0bca5d5c4feff66905d55ecaafdd839e80d0d0',
    '4ffc6402acca9aeb3b575a6eeef8b78c7990211a4e9005afb9607aebc970efd6',
    'c14068009f96d4ee99ee34733b6333357f4eee59f3e4f2296cfe52fbea2f565c',
    '978790788f7f897ed4dfdfd78da7cce61539e214dc881732ad429bcd54889dbf',
    '8efb33d23140507952cf0f394cad283f8ca088c22050dacd673db8dfe97588b3',
    '9a61143d062c5591d86b37b4081e7f77b13d2a464fbd08ab493c04515a6bb15f',
    '621428068d08e78d5ba08f2fec13969edfd0f0c81678e6ca86b8b2ff151cfd8f',
    '162a0a37b53583e20fd03281c4571e4d1041e4f083342b0ca41e448c5e427f7c',
    '18649fef2b4d541955ec6d89aa82a48dd1fe7fb2962a77519cb6733eceb78aa8',
    'af1ad7d9e46f16380cea72ad022072599ae406ff8f38e4c75afa236efbe5839e',
    '143f3229d9cbc7fdda52407439bba8d228cda7478cc68a038ec791247e587654',
    '0c4a1fffe341431ea24c7ed092fe143ed00680c5f17adfef052717903c67e33a',
    'a99f678b7c20f30c7dd22fd317889f9f97f49b3305b38f9709f77501f39e0be2',
    '2dfd9fb2160759a54d6f1c1a109fc40e6395b16af888000ed660add2ae770ff8',
    '662d9e241e783b1ae0b925a668982aac6cae76fdc56d5a20ebe93276cc8982c9',
    '78ecc61cb5cb70686d43fff30bc4013f94970a1f204b2d0a05832830eed96165',
    '95aa9d1674d7ad7c656dab39fb7d189470098f63424d0c2f146bba74f3508159',
    '528a7ce38ed8e21bd243ab81e4f2c94999b72b45c68a7c9412def1788dd8d04b',
    '362db4e94fbe822e97b25ee7c8976cbebd4a3d8f64c964f9f4148fb647b1c835',
    'f8f360dd6cd4a6efe21952d5c1eed2ca35d6abfe6e7eb984effbf43c9dc95e5c',
    '066970ccadd1176fdac1bb85f9f5b030872a4b01197c0c01f9de9155a65b7d57',
    'ee695a0c6c802dfbcb73d6e9ff1fbcf681961d3831b13a3f491fc2416d9e8606',
    'a6d4c755d1509b67bcb046bfe44c116321f3015a85f733e0208ef6068af39898',
    '18d565a47dd88f2d59406f5e879638164467ca45036e9db8fa76c9611e46b179',
    'd0e72741435521086b3ea72d8fa44029e70d3997ccf2f7e52ebbe11ca81d16ed',
    '1c268da1a1e39ced5d0e290e377073a79926fb02c1c1517de21c9deb285e2856',
    'aa3a407e1a1bdc6771a9c3d83fa0f071f2f31a685cde424397bb3eb2b7d5afe0',
    'ecd4d25fda64bec5382d506cf4778f322240923c11e6852fc390a6bff5608767',
    '9007636ca20718d81dc75c42d0a4cff5e843dc574617721298d47257b4402c97',
    '0c902ddeb2535ae495230304da995f494011bb3197aa545e4c56b7bf5f20d16d',
    '940b3a101e0dfc047567f3bc070c0e249063f6ffae088a96da7cf5ea20fbd739',
    '9ed180afeff294abdad087c62b242bcc03366e4db4b0408d7924d74a552430c6',
    'cec5f951c41b4cc18fa3ed09d351f820238362c34067414fb9d6bf40d251bf7a',
    '756c357e8e1b88fb2de042b92d0d3117cd12db4096c6e6bc68b54b6e9c5c24ec',
    'db33fe98ccb62c924a802f29deae511f64d60c47dec218c0bb29d651a22459fe',
    '0205035ce63221283a69a2afe8b9d1abf29099ef04eae33c476b877ea07d857e',
    'fdeb940310ab57682b1984bff6117652bca259ff039d02beaa4b6d98a27cce2d',
    'ecb84c2121c6a6ef6639d12423d533792031376309ee2a7671bdf5ddc294db4a',
    '2551e716e8ff5982fd5284d989d7284d0b178845793dd5e8a1e96ce2e2468c99',
    'fadca62eebd3a4494c5ad4075c9c05f3bf104c42d174d93acdac03260b4adf30',
    '1ede90eca1c448c51b4c7bbea84044de0537fc3e73ac6945da851e67c4fe7019',
    'bcd6e1fdd52c9166f29d475bea6e982f5d9d0de22efc162b80b4af31a6656703',
    '968971f706264da950171a610a00e390419ae892715f6438d65e40474f46222f',
    'fc52eeb928bed9504e95bc8d6ff8c2d00aef7e6dc8ac1d9d43e01e6f48775fb5',
    '85fd24a2965d78d834e52b28c4c92289acf97587ce7569404cf28b9d98c140b2',
  ].map(hexToBin);
  const sk = lmOtsSha256n32w4.generatePrivateKey(seed, I, q);
  const pk = lmOtsSha256n32w4.derivePublicKey(sk, I, q);
  expect(pk).toEqual(K);
  const message = thePowers;
  const sign = lmOtsSha256n32w4.sign(message, sk, I, q, C);
  const { signature: sig, Q, preImage, encodedMessageHash, checksum } = sign;
  expect(preImage).toEqual(expectedPreImage);
  expect(Q).toEqual(expectedQ);
  expect(checksum).toEqual(expectedChecksum);
  expect(encodedMessageHash).toEqual(expectedEncodedMessageHash);
  expect(lmOtsSha256n32w4.verify(message, sig, I, q, pk)).toBe(true);
  expect(sig.C).toEqual(C);
  expect(sig.Y[0]).toEqual(Y[0]);
  expect(sig.Y).toEqual(Y);
});

const typed = (len: number) =>
  fc
    .array(fc.integer({ min: 0, max: 255 }), { minLength: len, maxLength: len })
    .map((a) => Uint8Array.from(a));

const u8 = (len: number) => typed(len);
const msg = () =>
  fc
    .array(fc.integer({ min: 0, max: 255 }), { maxLength: 5000 })
    .map((a) => Uint8Array.from(a));
test('lmOtsSha256n32w4: round-trip success, failure on tamper', () => {
  fc.assert(
    fc.property(
      ...[u8(32), u8(16), fc.nat(10), u8(32), msg()],
      (seed, I, q, C, m) => {
        const sk = lmOtsSha256n32w4.generatePrivateKey(seed, I, q);
        const pk = lmOtsSha256n32w4.derivePublicKey(sk, I, q);
        const { signature } = lmOtsSha256n32w4.sign(m, sk, I, q, C);
        expect(lmOtsSha256n32w4.verify(m, signature, I, q, pk)).toBe(true);
        const tampered = { ...signature, C: signature.C.slice() };
        tampered.C[0] ^= 0xff;
        expect(lmOtsSha256n32w4.verify(m, tampered, I, q, pk)).toBe(false);
      }
    )
  );
});

test('lmOtsSha256n32w8: round-trip success, failure on tamper', () => {
  fc.assert(
    fc.property(
      ...[u8(32), u8(16), fc.nat(10), u8(32), msg()],
      (seed, I, q, C, m) => {
        const sk = lmOtsSha256n32w8.generatePrivateKey(seed, I, q);
        const pk = lmOtsSha256n32w8.derivePublicKey(sk, I, q);
        const { signature } = lmOtsSha256n32w8.sign(m, sk, I, q, C);
        expect(lmOtsSha256n32w8.verify(m, signature, I, q, pk)).toBe(true);
        const tampered = { ...signature, C: signature.C.slice() };
        tampered.C[0] ^= 0xff;
        expect(lmOtsSha256n32w8.verify(m, tampered, I, q, pk)).toBe(false);
      }
    )
  );
});

const template = assertSuccess(importWalletTemplate(templateJson));
const quantumrootVault = walletTemplateToCompilerConfiguration(template);
const compileWithVault = (script: string): Uint8Array => {
  const finalState = assertSuccess(
    evaluateCashAssembly(script, quantumrootVault)
  );
  const [top] = finalState.stack;
  return top;
};
const binToCashAssembly = (bin: Uint8Array) =>
  bin.length === 0 ? '' : `0x${binToHex(bin)}`;

/**
 * A sketch of the CashAssembly implementation. Looping backward saves a byte
 * or two in CashAssembly, coef is inlined, and all constants are baked in.
 */
const checksumOptimizedW4 = (Q: Uint8Array): number => {
  let sum = 0;
  for (let i = 31; i >= 0; --i) {
    const b = Q[i];
    const upper = b >>> 4;
    const lower = b & 0x0f;
    const contributes = 30 - (upper + lower);
    sum += contributes;
  }
  return sum << 4;
};

const checksumCashAssembly = (Q: Uint8Array): number =>
  Number(
    vmNumberToBigInt(
      compileWithVault(`<${binToCashAssembly(Q)}> lm-ots_checksum`)
    )
  );

test('CashAssembly optimized checksum', () => {
  const example = hexToBin(
    'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0'
  );
  const expectedExample = lmOtsSha256n32w4.checksum(example);
  expect(expectedExample).toBe(4096);
  const optimizedExample = checksumOptimizedW4(example);
  const cashAsmExample = checksumCashAssembly(example);
  expect(optimizedExample).toBe(expectedExample);
  expect(cashAsmExample).toBe(expectedExample);

  fc.assert(
    fc.property(...[u8(32)], (S) => {
      const expected = lmOtsSha256n32w4.checksum(S);
      const optimized = checksumOptimizedW4(S);
      const cashAsm = checksumCashAssembly(S);
      expect(optimized).toBe(expected);
      expect(cashAsm).toBe(expected);
    })
  );
});

const generatePrivateKeyCashAssembly = ({
  I,
  q,
  seed,
}: {
  seed: Uint8Array;
  I: Uint8Array;
  q: number;
}) =>
  compileWithVault(
    `
<${binToCashAssembly(I)}>
<${q}>
<${binToCashAssembly(seed)}>
lm-ots_private_key`
  );

const derivePublicKeyCashAssembly = ({
  I,
  q,
  x,
}: {
  x: Uint8Array;
  I: Uint8Array;
  q: number;
}) =>
  compileWithVault(
    `
<${binToCashAssembly(x)}>
<${binToCashAssembly(I)}>
<${q}>
<0>
lm-ots_public_key`
  );

const deriveKeyCandidateCashAssembly = ({
  C,
  I,
  message,
  q,
  Y,
}: {
  C: Uint8Array;
  I: Uint8Array;
  message: Uint8Array;
  q: number;
  Y: Uint8Array;
}): Uint8Array =>
  compileWithVault(
    `
<${binToCashAssembly(Y)}>
<${binToCashAssembly(I)}>
<${q}>
<${binToCashAssembly(C)}>
<${binToCashAssembly(message)}>
lm-ots_derive_key_candidate`
  );

const signCashAssembly = ({
  C,
  I,
  message,
  q,
  x,
}: {
  C: Uint8Array;
  I: Uint8Array;
  message: Uint8Array;
  q: number;
  x: Uint8Array;
}): Uint8Array =>
  compileWithVault(
    `
<${binToCashAssembly(x)}>
<${binToCashAssembly(I)}>
<${q}>
<${binToCashAssembly(C)}>
<${binToCashAssembly(message)}>
lm-ots_sign`
  );

test('CashAssembly implementations pass static vector', () => {
  const C = hexToBin(staticVector.C);
  const I = hexToBin(staticVector.I);
  const K = hexToBin(staticVector.K);
  const message = hexToBin(staticVector.message);
  const q = staticVector.q;
  const seed = hexToBin(staticVector.seed);
  const x = hexToBin(staticVector.x);
  const Y = hexToBin(staticVector.Y);
  const sk = lmOtsSha256n32w4.generatePrivateKey(seed, I, q);
  expect(binToHex(flattenBinArray(sk))).toEqual(staticVector.x);
  expect(binToHex(generatePrivateKeyCashAssembly({ I, q, seed }))).toEqual(
    staticVector.x
  );
  const pk = lmOtsSha256n32w4.derivePublicKey(sk, I, q);
  expect(binToHex(pk)).toEqual(staticVector.K);
  expect(binToHex(derivePublicKeyCashAssembly({ I, q, x }))).toEqual(
    staticVector.K
  );
  const { signature } = lmOtsSha256n32w4.sign(message, sk, I, q, C);
  expect(binToHex(flattenBinArray(signature.Y))).toEqual(staticVector.Y);
  expect(binToHex(signCashAssembly({ C, I, message, q, x }))).toEqual(
    staticVector.Y
  );
  expect(
    binToHex(deriveKeyCandidateCashAssembly({ C, I, message, q, Y }))
  ).toEqual(staticVector.K);
});

test('CashAssembly round-trip is equivalent to TS implementation', () => {
  fc.assert(
    fc.property(...[u8(32), u8(16), u8(32), msg()], (seed, I, C, m) => {
      const q = 0; // Only OTS is supported (better privacy, shorter contract)
      const sk = lmOtsSha256n32w4.generatePrivateKey(seed, I, q);
      const x = generatePrivateKeyCashAssembly({ I, q, seed });
      expect(flattenBinArray(sk)).toEqual(x);

      const pk = lmOtsSha256n32w4.derivePublicKey(sk, I, q);
      const K = derivePublicKeyCashAssembly({ I, q, x });
      expect(pk).toEqual(K);

      const { signature } = lmOtsSha256n32w4.sign(m, sk, I, q, C);
      const Y = signCashAssembly({ C, I, message: m, q, x });
      expect(flattenBinArray(signature.Y)).toEqual(Y);

      const Kc = deriveKeyCandidateCashAssembly({ C, I, message: m, q, Y });
      expect(Kc).toEqual(K);

      expect(lmOtsSha256n32w4.verify(m, signature, I, q, pk)).toBe(true);
      const tampered = { ...signature, C: signature.C.slice() };
      tampered.C[0] ^= 0xff;
      expect(lmOtsSha256n32w4.verify(m, tampered, I, q, pk)).toBe(false);
    })
  );
});

const vm = createVirtualMachineBch2026();
const compiler = createCompilerBch(quantumrootVault);

test('Validate template scenarios', () => {
  const quantumUnlock = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'quantum_unlock',
      scenarioId: 'aggregated_spend_slot_0',
    })
  );
  expect(vm.verify(quantumUnlock.program)).toBe(true);

  const quantumUnlockViaIntrospection = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'quantum_lock_introspection_unlock',
      scenarioId: 'aggregated_spend_slot_8',
    })
  );
  expect(vm.verify(quantumUnlockViaIntrospection.program)).toBe(true);

  const quantumIntrospectionBypassAttempt = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'quantum_lock_introspection_unlock',
      scenarioId: 'paired_bypass_attempt_quantum_lock',
    })
  );
  expect(vm.verify(quantumIntrospectionBypassAttempt.program)).toBe(
    'Unable to verify transaction: error in evaluating input index 0: Unsuccessful evaluation: completed with a non-truthy value on top of the stack. Top stack item: "".'
  );

  const receiveAddressSchnorrSpend = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'schnorr_spend',
      scenarioId: 'pre_quantum_aggregated_spend',
    })
  );
  expect(vm.verify(receiveAddressSchnorrSpend.program)).toBe(true);

  const receiveAddressTokenSpend = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'token_spend',
      scenarioId: 'aggregated_spend_slot_1',
    })
  );
  expect(vm.verify(receiveAddressTokenSpend.program)).toBe(true);

  const receiveAddressIntrospectionSpend = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'introspection_spend',
      scenarioId: 'aggregated_spend_slot_3',
    })
  );
  expect(vm.verify(receiveAddressIntrospectionSpend.program)).toBe(true);
  const receiveAddressBypassAttempt = assertSuccess(
    compiler.generateScenario({
      unlockingScriptId: 'introspection_spend',
      scenarioId: 'paired_bypass_attempt_receive_address',
    })
  );
  expect(vm.verify(receiveAddressBypassAttempt.program)).toBe(
    'Unable to verify transaction: error in evaluating input index 0: Unsuccessful evaluation: completed with a non-truthy value on top of the stack. Top stack item: "".'
  );

  const preQuantum = stringify({
    decoded: {
      sourceOutputs: receiveAddressSchnorrSpend.program.sourceOutputs,
      transaction: receiveAddressSchnorrSpend.program.transaction,
    },
    encodedHex: {
      sourceOutputs: encodeTransactionOutputs(
        receiveAddressSchnorrSpend.program.sourceOutputs
      ),
      transaction: encodeTransaction(
        receiveAddressSchnorrSpend.program.transaction
      ),
    },
  });
  const postQuantum = stringify({
    decoded: {
      sourceOutputs: receiveAddressTokenSpend.program.sourceOutputs,
      transaction: receiveAddressTokenSpend.program.transaction,
    },
    encodedHex: {
      sourceOutputs: encodeTransactionOutputs(
        receiveAddressTokenSpend.program.sourceOutputs
      ),
      transaction: encodeTransaction(
        receiveAddressTokenSpend.program.transaction
      ),
    },
  });
  expect(preQuantum).not.toEqual(postQuantum);

  const transaction = hexToBin(
    '02000000020100000000000000000000000000000000000000000000000000000000000000000000006a47304402204a86326ea6e2abb2ba73d490cd3293bdb7ff35886f9571064fb61e3dc64cb28b0220239338de5a5b1d54f7ff07196e16d10456da74b11ef1a79fc1bb02a084a977fd412103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e785000000000100000000000000000000000000000000000000000000000000000000000000010000006441de6174892e09d0b5d48c69d76cd4510d0254fd4a35edb6283454b0be48aa8db13c7d5b4cc84019cdf82a87c5bef2fc7768a7f249b681be49480e61a0b093b2a6412103a524f43d6166ad3567f18b0a5c769c6ab4dc02149f4d5095ccf4e8ffa293e7850000000002a0860100000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac32850100000000001976a9144af864646d46ee5a12f4695695ae78f993cad77588ac00000000'
  );
  const sourceOutputs = hexToBin(
    '02a0860100000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488aca0860100000000001976a91460011c6bf3f1dd98cff576437b9d85de780f497488ac'
  );
  const decoded = {
    sourceOutputs: assertSuccess(decodeTransactionOutputs(sourceOutputs)),
    transaction: assertSuccess(decodeTransaction(transaction)),
  };
  const baselineP2pkh = stringify({
    decoded,
    encodedHex: { sourceOutputs, transaction },
  });
  const utxo = decoded.sourceOutputs[1];
  const ecdsaInput = decoded.transaction.inputs[0];
  const schnorrInput = decoded.transaction.inputs[1];
  expect(utxo.lockingBytecode.length).toEqual(25);
  expect(ecdsaInput.unlockingBytecode.length).toEqual(106);
  expect(schnorrInput.unlockingBytecode.length).toEqual(100);

  Bun.write('./baseline-p2pkh-spend.json', baselineP2pkh);

  const sorted = sortObjectKeys(template);
  expect(templateJson).toStrictEqual(sorted);

  Bun.write('./pre-quantum-aggregated-spend.json', preQuantum);
  Bun.write('./post-quantum-aggregated-spend.json', postQuantum);
  Bun.write('./sorted-template.json', stringify(sorted));
});
