import { readFileSync } from 'node:fs';
import { expect } from 'bun:test';
import {
  assertSuccess,
  binsAreEqual,
  binToHex,
  createCompilerBch,
  createVirtualMachineBch2026,
  decodeTransaction,
  decodeTransactionOutputs,
  encodeTransaction,
  encodeTransactionOutputs,
  hashTransaction,
  hdPrivateKeyToIdentifier,
  hdPrivateKeyToP2pkhLockingBytecode,
  hexToBin,
  importWalletTemplate,
  lockingBytecodeToCashAddress,
  range,
  stringify,
  stringifyDebugTraceSummary,
  summarizeDebugTrace,
  swapEndianness,
  walletTemplateP2pkh,
  walletTemplateToCompilerConfiguration,
  type WalletTemplateScenario,
} from '@bitauth/libauth';
import templateJson from '../quantumroot-schnorr-lm-ots-vault.json';
const quantumrootTemplate = assertSuccess(importWalletTemplate(templateJson));
const template = {
  ...quantumrootTemplate,
  entities: {
    ...quantumrootTemplate.entities,
    p2pkhOwner: walletTemplateP2pkh.entities['owner'],
  },
  scripts: { ...quantumrootTemplate.scripts, ...walletTemplateP2pkh.scripts },
};

const fundingTransactionPath = './funding-transaction.hex';
/**
 * Accept two separate HD private keys, since it's far too easy to expose m/0 of
 * the funding key right now (default behavior of Libauth's `yarn wallet`).
 */
const usageInfo = `
This utility generates a series of transactions demonstrating various Quantumroot constructions and P2PKH-based equivalents for comparison. To setup/fund, use Libauth's "yarn wallet" package script.

  Usage: bun run demo.ts <vault_hd_private_key> <funding_hd_private_key> [funding_tx_hex]
   E.g.: bun run demo.ts xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta xprv9s21ZrQH143K2JbpEjGU94NcdKSASB7LuXvJCTsxuENcGN1nVG7QjMnBZ6zZNcJaiJogsRaLaYFFjs48qt4Fg7y1GnmrchQt1zFNu6QVnta 020000...

For [funding_tx_hex], provide the full, encoded funding transaction. If omitted, the script will attempt to read from ${fundingTransactionPath}.
`;

const [, , arg1, arg2, arg3] = process.argv;
const fundingAddressIndex = 0;

if (arg1 === undefined || arg2 === undefined) {
  console.log(usageInfo);
  process.exit(0);
}

const fundingTransactionBin =
  arg3 === undefined
    ? hexToBin(readFileSync(fundingTransactionPath, 'utf8'))
    : hexToBin(arg3);

const vaultHdPrivateKey = arg1;
const vaultKeyIdBin = hdPrivateKeyToIdentifier(arg1);
if (typeof vaultKeyIdBin === 'string') {
  console.log('\n', vaultKeyIdBin);
  process.exit(1);
}
const fundingHdPrivateKey = arg2;
const fundingKeyIdBin = hdPrivateKeyToIdentifier(arg2);
if (typeof fundingKeyIdBin === 'string') {
  console.log('\n', fundingKeyIdBin);
  process.exit(1);
}
const vaultKeyIdHex = binToHex(vaultKeyIdBin);
const fundingKeyIdHex = binToHex(fundingKeyIdBin);
console.log(`
HD private keys are valid. IDs of provided HD keys: 

Funding: ${fundingKeyIdHex} (using address index ${fundingAddressIndex})
Vault:   ${vaultKeyIdHex}`);
const fundingLockingBytecode = hdPrivateKeyToP2pkhLockingBytecode({
  addressIndex: fundingAddressIndex,
  hdPrivateKey: fundingHdPrivateKey,
});
const fundingAddressMainnet = assertSuccess(
  lockingBytecodeToCashAddress({
    bytecode: fundingLockingBytecode,
    prefix: 'bitcoincash',
  })
).address;
const fundingAddressTestnet = assertSuccess(
  lockingBytecodeToCashAddress({
    bytecode: fundingLockingBytecode,
    prefix: 'bchtest',
  })
).address;
console.log(`
Funding locking bytecode: ${binToHex(fundingLockingBytecode)}
Funding CashAddress (mainnet):  ${fundingAddressMainnet}
Funding CashAddress (testnet):      ${fundingAddressTestnet}
`);
const fundingTxId = hashTransaction(fundingTransactionBin);
console.log(`TXID (hash) of provided funding transaction: ${fundingTxId}`);
const fundingTransaction = assertSuccess(
  decodeTransaction(fundingTransactionBin)
);

const fundingUtxoIndex = fundingTransaction.outputs.findIndex((output) =>
  binsAreEqual(output.lockingBytecode, fundingLockingBytecode)
);

if (fundingUtxoIndex === -1) {
  console.log(
    `The provided funding transaction does not have an output which pays to address index ${fundingAddressIndex} of the provided HD private key (HD Key ID: ${fundingKeyIdHex}). Is this the correct funding transaction?
`
  );
  process.exit(1);
}
// eslint-disable-next-line @typescript-eslint/no-non-null-assertion
const fundingUtxo = fundingTransaction.outputs[fundingUtxoIndex]!;
type Utxo = typeof fundingUtxo;

console.log(
  `Extracted funding UTXO (output ${fundingUtxoIndex} of ${fundingTxId}):`,
  stringify(fundingUtxo)
);

const vm = createVirtualMachineBch2026(true);
const vmNonstandard = createVirtualMachineBch2026(false);
const verifyAndEncode = (
  path: string,
  scenarioGeneration: typeof tokenSetupGen,
  /**
   * To verify the compiled result: the serialized array of UTXOs we intended to spend.
   */
  recheckUtxos: Uint8Array,
  changeOutput?: number,
  nonstandard = false
) => {
  console.log(`Verifying and writing ${path}...`);
  if (typeof scenarioGeneration === 'string') {
    console.log(`Error while generating ${path}: ${scenarioGeneration}`);
    process.exit(1);
  }
  if (typeof scenarioGeneration.scenario === 'string') {
    console.log(
      `Error while generating ${path} scenario - ${scenarioGeneration.scenario}`
    );
    process.exit(1);
  }

  const transaction = scenarioGeneration.scenario.program.transaction;
  const sourceOutputs = scenarioGeneration.scenario.program.sourceOutputs;
  const resultingUtxos = encodeTransactionOutputs(sourceOutputs);
  if (!binsAreEqual(recheckUtxos, resultingUtxos)) {
    console.log(`
Verification error (${path}): the compiled UTXOs and expected UTXOs are different. Verify that the scenario's sourceOutputs are correct.

`);
    const expected = decodeTransactionOutputs(recheckUtxos);
    const compiled = decodeTransactionOutputs(resultingUtxos);
    console.log(
      stringify({
        // compiled,
        // expected,
        lengthCompiled: compiled.length,
        lengthExpected: expected.length,
      })
    );
    expect(compiled).toEqual(expected);
    process.exit(1);
  }

  const testTx = nonstandard
    ? vmNonstandard.verify(scenarioGeneration.scenario.program)
    : vm.verify(scenarioGeneration.scenario.program);
  if (testTx !== true) {
    console.log(`Transaction (${path}) is invalid: ${testTx}`);
    const inputIndex =
      typeof testTx === 'string'
        ? Number(
            /error in evaluating input index (\d+)/.exec(testTx)?.[1] ?? NaN
          )
        : NaN;
    if (!Number.isNaN(inputIndex)) {
      console.log(`Trace at input ${inputIndex}:`);
      const trace = vm.debug({ inputIndex, sourceOutputs, transaction });
      console.log(
        stringifyDebugTraceSummary(summarizeDebugTrace(trace), {
          printLineCount: 50,
        })
      );
    }
    process.exit(1);
  }
  const transactionBin = encodeTransaction(transaction);
  const txId = hashTransaction(transactionBin);
  const transactionHex = binToHex(transactionBin);

  const utxoSatoshis = scenarioGeneration.scenario.program.sourceOutputs.reduce(
    (utxoSats, utxo) => utxoSats + utxo.valueSatoshis,
    0n
  );
  const outputSatoshis = transaction.outputs.reduce(
    (outSats, output) => outSats + output.valueSatoshis,
    0n
  );
  const minerFee = Number(utxoSatoshis - outputSatoshis);
  const excessSatoshis = minerFee - transactionBin.length;
  const feeRate = transactionBin.length / minerFee;
  const changeOutputIndex = changeOutput ?? transaction.outputs.length - 1;
  const changeValue = Number(
    transaction.outputs[changeOutputIndex].valueSatoshis
  );
  if (feeRate !== 1) {
    console.log(`
Imperfect fee for ${path}. Transaction is ${
      transactionBin.length
    } bytes, but fee is ${minerFee}.

Increase output satoshis by: ${excessSatoshis} satoshis (e.g. set change output ${changeOutputIndex} to ${
      excessSatoshis + changeValue
    })
`);
  }
  Bun.file(path).write(transactionHex);
  // Bun.file(`${path}.debug.json`).write(
  //   stringify({ sourceOutputs, transaction })
  // );
  console.log(
    `Wrote ${path}. TXID: ${txId}, ${transactionBin.length} bytes, ${transaction.inputs.length} inputs, ${transaction.outputs.length} outputs`
  );
  return { transaction, hex: transactionHex, txId };
};

const onePlusFees = 100_000_000 + 1_000;
const sweepAdvantageSize = 6;

/**
 * Plan:
 * - Start from from funding input, then
 * - Create a token category (setup transaction, then mint token + quantum lock), with change output
 * - Create P2PKH fan-out transaction, with change output (index 0 for ease of block explorer viewing)
 * - Create pre-quantum fan-out transaction, with change output (index 0)
 * - Create post-quantum fan-out transaction.
 *
 * From P2PKH fan-out:
 * - 2 in (unique), 2 out,
 * - sweepAdvantageSize in (matching), 1 out,
 * - max in (matching), 1 out
 * - max in (unique), 1 out
 *
 * From Pre-Quantum fan-out:
 * - 2 in (unique), 2 out,
 * - sweepAdvantageSize in (matching), 1 out,
 * - max in (matching), 1 out,
 * - max in (unique), 1 out
 *
 * From Post-Quantum fan-out:
 * - 1 in, 1 out,
 * - 2 in (matching), 2 out,
 * - 2 in (unique), 2 out, (1 in, 1 out for token)
 * - max in (matching), 1 out,
 * - max in (unique), 1 out
 */

const tokenSetupInfo = {
  path: './demo/token-setup-transaction.hex',
  utxoSats: Number(fundingUtxo.valueSatoshis),
  outpoint: {
    hash: fundingTxId,
    index: fundingUtxoIndex,
  },
};
console.log(`Generating: ${tokenSetupInfo.path}`);
/**
 * Create a vault token category (production vaults can use and/or rotate across multiple).
 */
const tokenSetupGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      manual: {
        data: {
          hdKeys: { hdPrivateKeys: { p2pkhOwner: fundingHdPrivateKey } },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: tokenSetupInfo.utxoSats,
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: tokenSetupInfo.outpoint.index,
              outpointTransactionHash: tokenSetupInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 999999999815,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const tokenSetup = verifyAndEncode(
  tokenSetupInfo.path,
  tokenSetupGen,
  encodeTransactionOutputs([fundingUtxo])
);

const vaultCategory = tokenSetup.txId;
const data = {
  bytecode: {
    leaf_spend_index: '1',
    online_quantum_signer: '0',
    quantum_spend_index: '0',
    token_spend_index: '0',
    vault_token_category: `0x${swapEndianness(vaultCategory)}`,
  },
  hdKeys: {
    hdPrivateKeys: {
      owner: vaultHdPrivateKey,
      p2pkhOwner: fundingHdPrivateKey,
    },
  },
};

const tokenCreationInfo = {
  path: './demo/token-creation-transaction.hex',
  outpoint: {
    index: 0,
    hash: tokenSetup.txId,
  },
  utxoSats: Number(tokenSetup.transaction.outputs[0].valueSatoshis),
};
const tokenAddressIndex = 100_000;
const token = { category: vaultCategory, nft: { commitment: '' } };
console.log(`Generating: ${tokenCreationInfo.path}`);
const tokenCreationGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      manual: {
        data,
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: tokenCreationInfo.utxoSats,
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: tokenCreationInfo.outpoint.index,
              outpointTransactionHash: tokenCreationInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: tokenAddressIndex } },
              },
              token,
              valueSatoshis: 10_000,
            },
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 999999989552,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const tokenCreation = verifyAndEncode(
  tokenCreationInfo.path,
  tokenCreationGen,
  encodeTransactionOutputs([tokenSetup.transaction.outputs[0]])
);

const p2pkhMaxOutputs = 708;

const p2pkhFanOutInfo = {
  path: './demo/p2pkh-fan-out-transaction.hex',
  outpoint: {
    hash: tokenCreation.txId,
    index: tokenCreation.transaction.outputs.length - 1,
  },
  utxoSats: Number(tokenCreation.transaction.outputs.at(-1)!.valueSatoshis),
};
console.log(`Generating: ${p2pkhFanOutInfo.path}`);
/**
 * Fan out P2PKH outputs to create various P2PKH sweeps.
 */
const p2pkhFanOutGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      manual: {
        data,
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: p2pkhFanOutInfo.utxoSats,
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: p2pkhFanOutInfo.outpoint.index,
              outpointTransactionHash: p2pkhFanOutInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 857598516949,
            },
            ...range(2, 1).map((i) => ({
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(sweepAdvantageSize).map((i) => ({
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(p2pkhMaxOutputs).map((i) => ({
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 13 } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(p2pkhMaxOutputs, 14).map((i) => ({
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees,
            })),
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const p2pkhFanOut = verifyAndEncode(
  p2pkhFanOutInfo.path,
  p2pkhFanOutGen,
  encodeTransactionOutputs([tokenCreation.transaction.outputs[1]]),
  0
);

const p2pkhTwosInfo = {
  path: './demo/p2pkh-2-in-2-out-transaction.hex',
  outpoint: { hash: p2pkhFanOut.txId },
  outputIndex: { a: 1, b: 2 },
  addressIndex: { a: 1, b: 2 },
};
console.log(`Generating: ${p2pkhTwosInfo.path}`);
const p2pkhTwosGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: p2pkhTwosInfo.addressIndex.a } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[p2pkhTwosInfo.outputIndex.a]
                .valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'lock',
              overrides: {
                hdKeys: { addressIndex: p2pkhTwosInfo.addressIndex.b },
              },
            },
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[p2pkhTwosInfo.outputIndex.b]
                .valueSatoshis
            ),
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: p2pkhTwosInfo.outputIndex.a,
              outpointTransactionHash: p2pkhTwosInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: p2pkhTwosInfo.outputIndex.b,
              outpointTransactionHash: p2pkhTwosInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'unlock',
                overrides: {
                  hdKeys: { addressIndex: p2pkhTwosInfo.addressIndex.b },
                },
              },
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 150001640,
            },
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: 50_000_000,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const p2pkhTwosOut = verifyAndEncode(
  p2pkhTwosInfo.path,
  p2pkhTwosGen,
  encodeTransactionOutputs([
    p2pkhFanOut.transaction.outputs[p2pkhTwosInfo.outputIndex.a],
    p2pkhFanOut.transaction.outputs[p2pkhTwosInfo.outputIndex.b],
  ]),
  0
);

const p2pkhSwAdInfo = {
  path: `./demo/p2pkh-${sweepAdvantageSize}-in-1-out-transaction.hex`,
  outpoint: { hash: p2pkhFanOut.txId },
  outputIndexStart: 3,
  addressIndex: 3,
  outputCount: sweepAdvantageSize,
};
console.log(`Generating: ${p2pkhSwAdInfo.path}`);
const p2pkhSwAdGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: p2pkhSwAdInfo.addressIndex } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[p2pkhSwAdInfo.outputIndexStart]
                .valueSatoshis
            ),
          },
          ...range(
            p2pkhSwAdInfo.outputCount - 1,
            p2pkhSwAdInfo.outputIndexStart + 1
          ).map((i) => ({
            lockingBytecode: {
              script: 'lock',
              overrides: {
                hdKeys: { addressIndex: p2pkhSwAdInfo.addressIndex },
              },
            },
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[i].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: p2pkhSwAdInfo.outputIndexStart,
              outpointTransactionHash: p2pkhSwAdInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            ...range(
              p2pkhSwAdInfo.outputCount - 1,
              p2pkhSwAdInfo.outputIndexStart + 1
            ).map((i) => ({
              outpointIndex: i,
              outpointTransactionHash: p2pkhSwAdInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'unlock',
                overrides: {
                  hdKeys: { addressIndex: p2pkhSwAdInfo.addressIndex },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 600005110,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const p2pkhSwAdOutputIndexEnd =
  p2pkhSwAdInfo.outputIndexStart + p2pkhSwAdInfo.outputCount;
const p2pkhSwAdOut = verifyAndEncode(
  p2pkhSwAdInfo.path,
  p2pkhSwAdGen,
  encodeTransactionOutputs(
    p2pkhFanOut.transaction.outputs.slice(
      p2pkhSwAdInfo.outputIndexStart,
      p2pkhSwAdOutputIndexEnd
    )
  ),
  0
);

const p2pkhMaSweepInfo = {
  path: './demo/p2pkh-matching-sweep-transaction.hex',
  outpoint: { hash: p2pkhFanOut.txId },
  outputIndexStart: p2pkhSwAdOutputIndexEnd,
  addressIndexFixed: 13,
  outputCount: p2pkhMaxOutputs,
};
console.log(`Generating: ${p2pkhMaSweepInfo.path}`);
const p2pkhMaSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: p2pkhMaSweepInfo.addressIndexFixed } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[p2pkhMaSweepInfo.outputIndexStart]
                .valueSatoshis
            ),
          },
          ...range(
            p2pkhMaSweepInfo.outputCount - 1,
            p2pkhMaSweepInfo.outputIndexStart + 1
          ).map((i) => ({
            lockingBytecode: { script: 'lock' },
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[i].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: p2pkhMaSweepInfo.outputIndexStart,
              outpointTransactionHash: p2pkhMaSweepInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            ...range(
              p2pkhMaSweepInfo.outputCount - 1,
              p2pkhMaSweepInfo.outputIndexStart + 1
            ).map((i) => ({
              outpointIndex: i,
              outpointTransactionHash: p2pkhMaSweepInfo.outpoint.hash,
              unlockingBytecode: { script: 'unlock' },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 70800608126,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const p2pkhMaSweepOutputIndexEnd =
  p2pkhMaSweepInfo.outputIndexStart + p2pkhMaSweepInfo.outputCount;
const p2pkhMaSweepOut = verifyAndEncode(
  p2pkhMaSweepInfo.path,
  p2pkhMaSweepGen,
  encodeTransactionOutputs(
    p2pkhFanOut.transaction.outputs.slice(
      p2pkhMaSweepInfo.outputIndexStart,
      p2pkhMaSweepOutputIndexEnd
    )
  ),
  0
);

const p2pkhUniqSweepInfo = {
  path: './demo/p2pkh-unique-sweep-transaction.hex',
  outpoint: { hash: p2pkhFanOut.txId },
  outputIndexStart: p2pkhMaSweepOutputIndexEnd,
  addressIndexStart: 14,
  outputCount: p2pkhMaxOutputs,
};
console.log(`Generating: ${p2pkhUniqSweepInfo.path}`);
const p2pkhUniqSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          hdKeys: { addressIndex: p2pkhUniqSweepInfo.addressIndexStart },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[
                p2pkhUniqSweepInfo.outputIndexStart
              ].valueSatoshis
            ),
          },
          ...range(p2pkhUniqSweepInfo.outputCount - 1).map((i) => ({
            lockingBytecode: {
              script: 'lock',
              overrides: {
                hdKeys: {
                  addressIndex: i + 1 + p2pkhUniqSweepInfo.addressIndexStart,
                },
              },
            },
            valueSatoshis: Number(
              p2pkhFanOut.transaction.outputs[
                i + 1 + p2pkhUniqSweepInfo.outputIndexStart
              ].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: p2pkhUniqSweepInfo.outputIndexStart,
              outpointTransactionHash: p2pkhUniqSweepInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            ...range(p2pkhUniqSweepInfo.outputCount - 1).map((i) => ({
              outpointIndex: i + 1 + p2pkhUniqSweepInfo.outputIndexStart,
              outpointTransactionHash: p2pkhUniqSweepInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'unlock',
                overrides: {
                  hdKeys: {
                    addressIndex: i + 1 + p2pkhUniqSweepInfo.addressIndexStart,
                  },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 70800608126,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});
const p2pkhUniqSweepOut = verifyAndEncode(
  p2pkhUniqSweepInfo.path,
  p2pkhUniqSweepGen,
  encodeTransactionOutputs(
    p2pkhFanOut.transaction.outputs.slice(
      p2pkhUniqSweepInfo.outputIndexStart,
      p2pkhUniqSweepInfo.outputIndexStart + p2pkhUniqSweepInfo.outputCount
    )
  ),
  0
);

const preQMaxOutputs = 891;
const preQUniqOutputs = 459;

const preQFanOutInfo = {
  path: './demo/pre-quantum-fan-out-transaction.hex',
  outpoint: { index: 0, hash: p2pkhFanOut.txId },
  utxoSats: Number(p2pkhFanOut.transaction.outputs[0].valueSatoshis),
};
console.log(`Generating: ${preQFanOutInfo.path}`);
/**
 * Fan out for pre-quantum vault sweeps.
 */
const preQFanOutGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      manual: {
        data,
        sourceOutputs: [
          { lockingBytecode: ['slot'], valueSatoshis: preQFanOutInfo.utxoSats },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: preQFanOutInfo.outpoint.index,
              outpointTransactionHash: preQFanOutInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 721797099010,
            },
            /**
             * We use address index 0 to collect final outputs (correctly demo length of P2SH32 outputs)
             */
            ...range(2, 1).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(sweepAdvantageSize).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(preQMaxOutputs).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 13 } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(preQUniqOutputs, 14).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees,
            })),
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});

const preQFanOut = verifyAndEncode(
  preQFanOutInfo.path,
  preQFanOutGen,
  encodeTransactionOutputs([p2pkhFanOut.transaction.outputs[0]]),
  0
);

const preQTwosInfo = {
  path: './demo/pre-quantum-2-in-2-out-transaction.hex',
  outpoint: { hash: preQFanOut.txId },
  outputIndex: { a: 1, b: 2 },
  addressIndex: { a: 1, b: 2 },
};
console.log(`Generating: ${preQTwosInfo.path}`);
const preQTwosGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: preQTwosInfo.addressIndex.a } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[preQTwosInfo.outputIndex.a]
                .valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: { addressIndex: preQTwosInfo.addressIndex.b },
              },
            },
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[preQTwosInfo.outputIndex.b]
                .valueSatoshis
            ),
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: preQTwosInfo.outputIndex.a,
              outpointTransactionHash: preQTwosInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: preQTwosInfo.outputIndex.b,
              outpointTransactionHash: preQTwosInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'schnorr_spend',
                overrides: {
                  hdKeys: { addressIndex: preQTwosInfo.addressIndex.b },
                },
              },
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 150001406,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: 50_000_000,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'schnorr_spend',
});
const preQTwosOut = verifyAndEncode(
  preQTwosInfo.path,
  preQTwosGen,
  encodeTransactionOutputs([
    preQFanOut.transaction.outputs[preQTwosInfo.outputIndex.a],
    preQFanOut.transaction.outputs[preQTwosInfo.outputIndex.b],
  ]),
  0
);

const preQSwAdInfo = {
  path: `./demo/pre-quantum-${sweepAdvantageSize}-in-1-out-transaction.hex`,
  outpoint: { hash: preQFanOut.txId },
  outputIndexStart: 3,
  addressIndex: 3,
  outputCount: sweepAdvantageSize,
};
console.log(`Generating: ${preQSwAdInfo.path}`);
const preQSwAdGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          bytecode: { leaf_spend_index: '0' },
          hdKeys: { addressIndex: preQSwAdInfo.addressIndex },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[preQSwAdInfo.outputIndexStart]
                .valueSatoshis
            ),
          },
          ...range(
            preQSwAdInfo.outputCount - 1,
            1 + preQSwAdInfo.outputIndexStart
          ).map((i) => ({
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: { addressIndex: preQSwAdInfo.addressIndex },
              },
            },
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[i].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: preQSwAdInfo.outputIndexStart,
              outpointTransactionHash: preQSwAdInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            ...range(
              preQSwAdInfo.outputCount - 1,
              1 + preQSwAdInfo.outputIndexStart
            ).map((i) => ({
              outpointIndex: i,
              outpointTransactionHash: preQSwAdInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'introspection_spend',
                overrides: {
                  hdKeys: { addressIndex: preQSwAdInfo.addressIndex },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 600005138,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'schnorr_spend',
});
const preQSwAdOutputIndexEnd =
  preQSwAdInfo.outputIndexStart + preQSwAdInfo.outputCount;
const preQSwAdOut = verifyAndEncode(
  preQSwAdInfo.path,
  preQSwAdGen,
  encodeTransactionOutputs(
    preQFanOut.transaction.outputs.slice(
      preQSwAdInfo.outputIndexStart,
      preQSwAdOutputIndexEnd
    )
  ),
  0
);

const preQMaSweepInfo = {
  path: './demo/pre-quantum-matching-sweep-transaction.hex',
  outpoint: { hash: preQFanOut.txId },
  outputIndexStart: preQSwAdOutputIndexEnd,
  addressIndexFixed: 13,
  outputCount: preQMaxOutputs,
};
console.log(`Generating: ${preQMaSweepInfo.path}`);
const preQMaSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          bytecode: { leaf_spend_index: '0' },
          hdKeys: { addressIndex: preQMaSweepInfo.addressIndexFixed },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[preQMaSweepInfo.outputIndexStart]
                .valueSatoshis
            ),
          },
          ...range(
            preQMaSweepInfo.outputCount - 1,
            preQMaSweepInfo.outputIndexStart + 1
          ).map((i) => ({
            lockingBytecode: { script: 'receive_address' },
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[i].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: preQMaSweepInfo.outputIndexStart,
              outpointTransactionHash: preQMaSweepInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
            ...range(
              preQMaSweepInfo.outputCount - 1,
              preQMaSweepInfo.outputIndexStart + 1
            ).map((i) => ({
              outpointIndex: i,
              outpointTransactionHash: preQMaSweepInfo.outpoint.hash,
              unlockingBytecode: { script: 'introspection_spend' },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 89100791016,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'schnorr_spend',
});
const preQMaSweepOutputIndexEnd =
  preQMaSweepInfo.outputIndexStart + preQMaSweepInfo.outputCount;
const preQMaSweepOut = verifyAndEncode(
  preQMaSweepInfo.path,
  preQMaSweepGen,
  encodeTransactionOutputs(
    preQFanOut.transaction.outputs.slice(
      preQMaSweepInfo.outputIndexStart,
      preQMaSweepOutputIndexEnd
    )
  ),
  0
);

const preQUniqSweepInfo = {
  path: './demo/pre-quantum-unique-sweep-transaction.hex',
  outpoint: { hash: preQFanOut.txId },
  outputIndexStart: preQMaSweepOutputIndexEnd,
  addressIndexStart: 14,
  outputCount: preQUniqOutputs,
};
console.log(`Generating: ${preQUniqSweepInfo.path}`);
const preQUniqSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          hdKeys: { addressIndex: tokenAddressIndex },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            token,
            valueSatoshis: Number(
              tokenCreation.transaction.outputs[0].valueSatoshis
            ),
          },
          ...range(preQUniqSweepInfo.outputCount).map((i) => ({
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: {
                  addressIndex: i + preQUniqSweepInfo.addressIndexStart,
                },
              },
            },
            valueSatoshis: Number(
              preQFanOut.transaction.outputs[
                i + preQUniqSweepInfo.outputIndexStart
              ].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: 0,
              outpointTransactionHash: tokenCreation.txId,
              unlockingBytecode: ['slot'],
            },
            ...range(preQUniqSweepInfo.outputCount).map((i) => ({
              outpointIndex: i + preQUniqSweepInfo.outputIndexStart,
              outpointTransactionHash: preQUniqSweepInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'token_spend',
                overrides: {
                  hdKeys: {
                    addressIndex: i + preQUniqSweepInfo.addressIndexStart,
                  },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: tokenAddressIndex } },
              },
              token,
              valueSatoshis: 10_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 45900359015,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'schnorr_spend',
});
const preQUniqSweepOut = verifyAndEncode(
  preQUniqSweepInfo.path,
  preQUniqSweepGen,
  encodeTransactionOutputs([
    tokenCreation.transaction.outputs[0],
    ...preQFanOut.transaction.outputs.slice(
      preQUniqSweepInfo.outputIndexStart,
      preQUniqSweepInfo.outputIndexStart + preQUniqSweepInfo.outputCount
    ),
  ]),
  1
);

const postQMaxOutputs = 868;
const postQUniqOutputs = 448;

const postQFanOutInfo = {
  path: './demo/post-quantum-fan-out-transaction.hex',
  outpoint: { index: 0, hash: preQFanOut.txId },
  utxoSats: Number(preQFanOut.transaction.outputs[0].valueSatoshis),
};
console.log(`Generating: ${postQFanOutInfo.path}`);
const postQFanOutGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      manual: {
        data,
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: postQFanOutInfo.utxoSats,
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: postQFanOutInfo.outpoint.index,
              outpointTransactionHash: postQFanOutInfo.outpoint.hash,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 589695709689,
            },
            /**
             * We use address index 0 to collect final outputs (correctly demo length of P2SH32 outputs)
             */
            ...range(2, 1).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees + 2000,
            })),
            ...range(postQMaxOutputs).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 13 } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(postQUniqOutputs, 14).map((i) => ({
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: i } },
              },
              valueSatoshis: onePlusFees,
            })),
            ...range(2).map((i) => ({
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: 3001 } },
              },
              valueSatoshis: onePlusFees + 2000,
            })),
            {
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: 3003 } },
              },
              valueSatoshis: onePlusFees + 2000,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});

const postQFanOut = verifyAndEncode(
  postQFanOutInfo.path,
  postQFanOutGen,
  encodeTransactionOutputs([preQFanOut.transaction.outputs[0]]),
  0
);

const postQSingleInfo = {
  path: './demo/post-quantum-1-in-1-out-transaction.hex',
  outputIndex: postQFanOut.transaction.outputs.length - 1,
};
console.log(`Generating: ${postQSingleInfo.path}`);
const postQSingleGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: 3003 } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[postQSingleInfo.outputIndex]
                .valueSatoshis
            ),
          },
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: postQSingleInfo.outputIndex,
              outpointTransactionHash: postQFanOut.txId,
              unlockingBytecode: ['slot'],
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 100000387,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'quantum_unlock',
});
const postQSingleOut = verifyAndEncode(
  postQSingleInfo.path,
  postQSingleGen,
  encodeTransactionOutputs([
    postQFanOut.transaction.outputs[postQSingleInfo.outputIndex],
  ]),
  0
);

const postQTwosMaInfo = {
  path: './demo/post-quantum-2-in-2-out-matching-transaction.hex',
  outputIndexStart: postQSingleInfo.outputIndex - 2,
};
console.log(`Generating: ${postQTwosMaInfo.path}`);
const postQTwosMaGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: 3001 } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[postQTwosMaInfo.outputIndexStart]
                .valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'quantum_lock',
              overrides: {
                hdKeys: { addressIndex: 3001 },
              },
            },
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[
                postQTwosMaInfo.outputIndexStart + 1
              ].valueSatoshis
            ),
          },
        ],
        transaction: {
          inputs: [
            {
              compilationOrder: 1,
              outpointIndex: postQTwosMaInfo.outputIndexStart,
              outpointTransactionHash: postQFanOut.txId,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: postQTwosMaInfo.outputIndexStart + 1,
              outpointTransactionHash: postQFanOut.txId,
              unlockingBytecode: {
                script: 'quantum_lock_introspection_unlock',
                overrides: {
                  hdKeys: { addressIndex: 3001 },
                },
              },
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 150_000_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: 50003077,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'quantum_unlock',
});
const postQTwosMaOut = verifyAndEncode(
  postQTwosMaInfo.path,
  postQTwosMaGen,
  encodeTransactionOutputs([
    postQFanOut.transaction.outputs.at(-3)!,
    postQFanOut.transaction.outputs.at(-2)!,
  ]),
  1
);

const postQTwosUniqInfo = {
  path: './demo/post-quantum-2-in-2-out-unique-transaction.hex',
  outpoint: { hash: postQFanOut.txId },
  outputIndex: { a: 1, b: 2 },
  addressIndex: { a: 1, b: 2 },
};
console.log(`Generating: ${postQTwosUniqInfo.path}`);
const postQTwosUniqGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: { hdKeys: { addressIndex: tokenAddressIndex } },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            token,
            valueSatoshis: Number(
              preQUniqSweepOut.transaction.outputs[0].valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: { addressIndex: postQTwosUniqInfo.addressIndex.a },
              },
            },
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[postQTwosUniqInfo.outputIndex.a]
                .valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: { addressIndex: postQTwosUniqInfo.addressIndex.b },
              },
            },
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[postQTwosUniqInfo.outputIndex.b]
                .valueSatoshis
            ),
          },
        ],
        transaction: {
          inputs: [
            {
              compilationOrder: 1,
              outpointIndex: 0,
              outpointTransactionHash: preQUniqSweepOut.txId,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: postQTwosUniqInfo.outputIndex.a,
              outpointTransactionHash: postQTwosUniqInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'token_spend',
                overrides: {
                  hdKeys: { addressIndex: postQTwosUniqInfo.addressIndex.a },
                },
              },
            },
            {
              outpointIndex: postQTwosUniqInfo.outputIndex.b,
              outpointTransactionHash: postQTwosUniqInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'token_spend',
                overrides: {
                  hdKeys: { addressIndex: postQTwosUniqInfo.addressIndex.b },
                },
              },
            },
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: tokenAddressIndex } },
              },
              token,
              valueSatoshis: 10_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 150_000_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
              valueSatoshis: 50002831,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'quantum_unlock',
});
const postQTwosUniqOut = verifyAndEncode(
  postQTwosUniqInfo.path,
  postQTwosUniqGen,
  encodeTransactionOutputs([
    preQUniqSweepOut.transaction.outputs[0],
    postQFanOut.transaction.outputs[postQTwosUniqInfo.outputIndex.a],
    postQFanOut.transaction.outputs[postQTwosUniqInfo.outputIndex.b],
  ]),
  2
);

const postQMaSweepInfo = {
  path: './demo/post-quantum-matching-sweep-transaction.hex',
  outpoint: { hash: postQFanOut.txId },
  outputIndexStart: 3,
  addressIndexFixed: 13,
  outputCount: postQMaxOutputs,
};
console.log(`Generating: ${postQMaSweepInfo.path}`);
const postQMaSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          bytecode: { online_quantum_signer: '1' },
          hdKeys: { addressIndex: tokenAddressIndex },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            token,
            valueSatoshis: Number(
              postQTwosUniqOut.transaction.outputs[0].valueSatoshis
            ),
          },
          ...range(
            postQMaSweepInfo.outputCount,
            postQMaSweepInfo.outputIndexStart
          ).map((i) => ({
            lockingBytecode: {
              overrides: {
                hdKeys: { addressIndex: postQMaSweepInfo.addressIndexFixed },
              },
              script: 'receive_address',
            },
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[i].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              compilationOrder: 1,
              outpointIndex: 0,
              outpointTransactionHash: postQTwosUniqOut.txId,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: postQMaSweepInfo.outputIndexStart,
              outpointTransactionHash: postQMaSweepInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'token_spend',
                overrides: {
                  hdKeys: { addressIndex: postQMaSweepInfo.addressIndexFixed },
                },
              },
            },
            ...range(
              postQMaSweepInfo.outputCount - 1,
              postQMaSweepInfo.outputIndexStart + 1
            ).map((i) => ({
              outpointIndex: i,
              outpointTransactionHash: postQMaSweepInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'introspection_spend',
                overrides: {
                  hdKeys: { addressIndex: postQMaSweepInfo.addressIndexFixed },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: tokenAddressIndex } },
              },
              token,
              valueSatoshis: 10_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 86800768004,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'quantum_unlock',
});
const postQMaSweepOutputIndexEnd =
  postQMaSweepInfo.outputIndexStart + postQMaSweepInfo.outputCount;
const postQMaSweepOut = verifyAndEncode(
  postQMaSweepInfo.path,
  postQMaSweepGen,
  encodeTransactionOutputs([
    postQTwosUniqOut.transaction.outputs[0],
    ...postQFanOut.transaction.outputs.slice(
      postQMaSweepInfo.outputIndexStart,
      postQMaSweepOutputIndexEnd
    ),
  ]),
  1
);

const postQUniqSweepInfo = {
  path: './demo/post-quantum-unique-sweep-transaction.hex',
  outpoint: { hash: postQFanOut.txId },
  outputIndexStart: postQMaSweepOutputIndexEnd,
  addressIndexStart: 14,
  outputCount: postQUniqOutputs,
};
console.log(`Generating: ${postQUniqSweepInfo.path}`);
const postQUniqSweepGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          bytecode: { online_quantum_signer: '1' },
          hdKeys: { addressIndex: tokenAddressIndex },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            token,
            valueSatoshis: Number(
              postQMaSweepOut.transaction.outputs[0].valueSatoshis
            ),
          },
          ...range(postQUniqSweepInfo.outputCount).map((i) => ({
            lockingBytecode: {
              script: 'receive_address',
              overrides: {
                hdKeys: {
                  addressIndex: i + postQUniqSweepInfo.addressIndexStart,
                },
              },
            },
            valueSatoshis: Number(
              postQFanOut.transaction.outputs[
                i + postQUniqSweepInfo.outputIndexStart
              ].valueSatoshis
            ),
          })),
        ],
        transaction: {
          inputs: [
            {
              compilationOrder: 1,
              outpointIndex: 0,
              outpointTransactionHash: postQMaSweepOut.txId,
              unlockingBytecode: ['slot'],
            },
            ...range(postQUniqSweepInfo.outputCount).map((i) => ({
              outpointIndex: i + postQUniqSweepInfo.outputIndexStart,
              outpointTransactionHash: postQUniqSweepInfo.outpoint.hash,
              unlockingBytecode: {
                script: 'token_spend',
                overrides: {
                  hdKeys: {
                    addressIndex: i + postQUniqSweepInfo.addressIndexStart,
                  },
                },
              },
            })),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'quantum_lock',
                overrides: { hdKeys: { addressIndex: tokenAddressIndex } },
              },
              token,
              valueSatoshis: 10_000,
            },
            {
              lockingBytecode: {
                script: 'receive_address',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 44800348109,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'quantum_unlock',
});
const postQUniqSweepOut = verifyAndEncode(
  postQUniqSweepInfo.path,
  postQUniqSweepGen,
  encodeTransactionOutputs([
    postQMaSweepOut.transaction.outputs[0],
    ...postQFanOut.transaction.outputs.slice(
      postQUniqSweepInfo.outputIndexStart,
      postQUniqSweepInfo.outputIndexStart + postQUniqSweepInfo.outputCount
    ),
  ]),
  1
);

const cleanupInfo = {
  path: './demo/cleanup-transaction.hex',
};

const cleanupInputs = [
  ...[
    // { tx: p2pkhTwosOut, outputIndex: 0, addressIndex: 0 },
    { tx: p2pkhTwosOut, outputIndex: 1, addressIndex: 3 },
    { tx: p2pkhSwAdOut, outputIndex: 0, addressIndex: 0 },
    { tx: p2pkhMaSweepOut, outputIndex: 0, addressIndex: 0 },
    { tx: p2pkhUniqSweepOut, outputIndex: 0, addressIndex: 0 },
  ].map(({ tx, addressIndex, outputIndex }) => ({
    valueSatoshis: Number(tx.transaction.outputs[outputIndex].valueSatoshis),
    outpointIndex: outputIndex,
    outpointTransactionHash: tx.txId,
    addressIndex,
    lockingBytecode: 'lock',
    unlockingBytecode: 'unlock',
    output: tx.transaction.outputs[outputIndex],
  })),
  ...[
    // { tx: preQTwosOut, outputIndex: 0, addressIndex: 0 },
    // { tx: preQTwosOut, outputIndex: 1, addressIndex: 3 },
    // { tx: postQTwosMaOut, outputIndex: 1, addressIndex: 3 },
    // { tx: postQTwosUniqOut, outputIndex: 2, addressIndex: 3 },
    { tx: preQMaSweepOut, outputIndex: 0, addressIndex: 0 },
    { tx: preQUniqSweepOut, outputIndex: 1, addressIndex: 0 },
    { tx: postQUniqSweepOut, outputIndex: 1, addressIndex: 0 },
    { tx: postQFanOut, outputIndex: 0, addressIndex: 0 },
    { tx: postQMaSweepOut, outputIndex: 1, addressIndex: 0 },
    { tx: postQSingleOut, outputIndex: 0, addressIndex: 0 },
    { tx: postQTwosMaOut, outputIndex: 0, addressIndex: 0 },
    { tx: postQTwosUniqOut, outputIndex: 1, addressIndex: 0 },
    { tx: preQSwAdOut, outputIndex: 0, addressIndex: 0 },
  ].map(({ tx, addressIndex, outputIndex }) => ({
    valueSatoshis: Number(tx.transaction.outputs[outputIndex].valueSatoshis),
    outpointIndex: outputIndex,
    outpointTransactionHash: tx.txId,
    addressIndex,
    lockingBytecode: 'receive_address',
    unlockingBytecode: 'introspection_spend',
    output: tx.transaction.outputs[outputIndex],
  })),
];

console.log(`Generating: ${cleanupInfo.path}`);
const cleanupGen = createCompilerBch(
  walletTemplateToCompilerConfiguration({
    ...template,
    scenarios: {
      inherit: { data },
      manual: {
        extends: 'inherit',
        data: {
          hdKeys: { addressIndex: 0 },
        },
        sourceOutputs: [
          {
            lockingBytecode: ['slot'],
            valueSatoshis: Number(
              p2pkhTwosOut.transaction.outputs[0].valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
            },
            valueSatoshis: Number(
              preQTwosOut.transaction.outputs[0].valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: { hdKeys: { addressIndex: 3 } },
            },
            valueSatoshis: Number(
              preQTwosOut.transaction.outputs[1].valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: { hdKeys: { addressIndex: 3 } },
            },
            valueSatoshis: Number(
              postQTwosMaOut.transaction.outputs[1].valueSatoshis
            ),
          },
          {
            lockingBytecode: {
              script: 'receive_address',
              overrides: { hdKeys: { addressIndex: 3 } },
            },
            valueSatoshis: Number(
              postQTwosUniqOut.transaction.outputs[2].valueSatoshis
            ),
          },
          ...cleanupInputs.map(
            ({ lockingBytecode, addressIndex, valueSatoshis }) => ({
              lockingBytecode: {
                script: lockingBytecode,
                overrides: { hdKeys: { addressIndex } },
              },
              valueSatoshis,
            })
          ),
        ],
        transaction: {
          inputs: [
            {
              outpointIndex: 0,
              outpointTransactionHash: p2pkhTwosOut.txId,
              unlockingBytecode: ['slot'],
            },
            {
              outpointIndex: 0,
              outpointTransactionHash: preQTwosOut.txId,
              unlockingBytecode: { script: 'schnorr_spend' },
            },
            {
              outpointIndex: 1,
              outpointTransactionHash: preQTwosOut.txId,
              unlockingBytecode: {
                script: 'introspection_spend',
                overrides: {
                  hdKeys: { addressIndex: 3 },
                  bytecode: { leaf_spend_index: '3' },
                },
              },
            },
            {
              outpointIndex: 1,
              outpointTransactionHash: postQTwosMaOut.txId,
              unlockingBytecode: {
                script: 'schnorr_spend',
                overrides: { hdKeys: { addressIndex: 3 } },
              },
            },
            {
              outpointIndex: 2,
              outpointTransactionHash: postQTwosUniqOut.txId,
              unlockingBytecode: {
                script: 'introspection_spend',
                overrides: {
                  bytecode: { leaf_spend_index: '3' },
                  hdKeys: { addressIndex: 3 },
                },
              },
            },
            ...cleanupInputs.map(
              ({
                outpointIndex,
                outpointTransactionHash,
                unlockingBytecode,
                addressIndex,
              }) => ({
                outpointIndex,
                outpointTransactionHash,
                unlockingBytecode: {
                  script: unlockingBytecode,
                  overrides: { hdKeys: { addressIndex } },
                },
              })
            ),
          ],
          outputs: [
            {
              lockingBytecode: {
                script: 'lock',
                overrides: { hdKeys: { addressIndex: 0 } },
              },
              valueSatoshis: 999999209197,
            },
          ],
        },
      },
    },
  })
).generateScenario({
  debug: true,
  scenarioId: 'manual',
  unlockingScriptId: 'unlock',
});

const cleanupOut = verifyAndEncode(
  cleanupInfo.path,
  cleanupGen,
  encodeTransactionOutputs([
    p2pkhTwosOut.transaction.outputs[0],
    preQTwosOut.transaction.outputs[0],
    preQTwosOut.transaction.outputs[1],
    postQTwosMaOut.transaction.outputs[1],
    postQTwosUniqOut.transaction.outputs[2],
    ...cleanupInputs.map((i) => i.output),
  ]),
  0
);
