import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  assertSuccess,
  binToHex,
  decodeTransaction,
  hashTransaction,
  hexToBin,
} from '@bitauth/libauth';

type Transaction = Exclude<ReturnType<typeof decodeTransaction>, string>;

type ParsedTransaction = {
  fileName: string;
  hex: string;
  txid: string;
  transaction: Transaction;
};

type OutputMeta = {
  fileName: string;
  txid: string;
  vout: number;
  valueSatoshis: bigint;
  lockingBytecodeHex: string;
};

type UnknownInput = {
  fileName: string;
  txid: string;
  inputIndex: number;
  prevTxid: string;
  prevIndex: number;
};

type UnspentOutputReport = {
  fileName: string;
  txid: string;
  vout: number;
  valueSatoshis: string;
  lockingBytecodeHex: string;
};

type SpendRecord = {
  fileName: string;
  txid: string;
  inputIndex: number;
};

type DoubleSpend = {
  outpointTxid: string;
  outpointIndex: number;
  referenceCount: number;
  references: SpendRecord[];
};

type Report = {
  unknownInputs: UnknownInput[];
  unspentOutputs: UnspentOutputReport[];
  doubleSpends: DoubleSpend[];
};

type TableColumn<Row> = {
  header: string;
  getValue: (row: Row) => string;
};

type FundingInfo = {
  txid: string;
  transaction: Transaction;
};

const demoDir = fileURLToPath(new URL('./demo/', import.meta.url));
const fundingTransactionPath = fileURLToPath(
  new URL('./funding-transaction.hex', import.meta.url)
);
const tokenSetupFileName = 'token-setup-transaction.hex';
const cliExampleCommand =
  '~/bchn/build/src/bitcoin-cli -datadir=/bitcoin-bchn-tempnet';
const outpointKey = (txid: string, vout: number) => `${txid}:${vout}`;

const readHex = (path: string) =>
  readFileSync(path, 'utf8').replace(/\s+/g, '');

let fundingInfoCache: FundingInfo | undefined;
const getFundingInfo = (): FundingInfo => {
  if (fundingInfoCache !== undefined) return fundingInfoCache;
  const fundingHex = readHex(fundingTransactionPath);
  const fundingBin = hexToBin(fundingHex);
  fundingInfoCache = {
    transaction: assertSuccess(decodeTransaction(fundingBin)),
    txid: hashTransaction(fundingBin),
  };
  return fundingInfoCache;
};

const loadTransactions = (): ParsedTransaction[] => {
  const hexFiles = readdirSync(demoDir)
    .filter((file) => file.endsWith('.hex'))
    .sort();

  if (hexFiles.length === 0) {
    throw new Error(`No .hex transactions found in ${demoDir}`);
  }

  return hexFiles.map((fileName) => {
    const filePath = join(demoDir, fileName);
    const hex = readHex(filePath);
    const transactionBin = hexToBin(hex);
    const transaction = assertSuccess(decodeTransaction(transactionBin));
    const txid = hashTransaction(transactionBin);
    return { fileName, hex, txid, transaction };
  });
};

const formatNumber = (value: string) =>
  value.replace(/\B(?=(\d{3})+(?!\d))/g, ',');

const pad = (value: string, length: number) =>
  value.length < length
    ? `${value}${' '.repeat(length - value.length)}`
    : value;

const renderTable = <Row>(
  title: string,
  columns: TableColumn<Row>[],
  rows: Row[]
) => {
  console.log(`\n${title}`);
  if (rows.length === 0) {
    console.log('  (none)');
    return;
  }

  const stringRows = rows.map((row) =>
    columns.map((column) => column.getValue(row))
  );
  const widths = columns.map((column, index) =>
    Math.max(
      column.header.length,
      ...stringRows.map((row) => row[index].length)
    )
  );
  const divider = (char: string) =>
    `+-${widths.map((width) => char.repeat(width)).join('-+-')}-+`;
  const renderRow = (cells: string[]) =>
    `| ${cells.map((cell, i) => pad(cell, widths[i])).join(' | ')} |`;

  console.log(divider('-'));
  console.log(renderRow(columns.map((column) => column.header)));
  console.log(divider('='));
  stringRows.forEach((row) => console.log(renderRow(row)));
  console.log(divider('-'));
};

const summarize = (transactions: ParsedTransaction[]): Report => {
  const fundingInfo = getFundingInfo();
  const outputs = new Map<string, OutputMeta>();
  for (const { fileName, txid, transaction } of transactions) {
    transaction.outputs.forEach((output, vout) => {
      outputs.set(outpointKey(txid, vout), {
        fileName,
        lockingBytecodeHex: binToHex(output.lockingBytecode),
        txid,
        valueSatoshis: output.valueSatoshis,
        vout,
      });
    });
  }

  const spent = new Set<string>();
  const spendRecords = new Map<string, SpendRecord[]>();
  const unknownInputs: UnknownInput[] = [];

  const isFundingOutpoint = (prevTxid: string, prevIndex: number) =>
    prevTxid === fundingInfo.txid &&
    prevIndex >= 0 &&
    fundingInfo.transaction.outputs[prevIndex] !== undefined;

  for (const { fileName, txid, transaction } of transactions) {
    transaction.inputs.forEach((input, inputIndex) => {
      const prevTxid = binToHex(input.outpointTransactionHash);
      const key = outpointKey(prevTxid, input.outpointIndex);
      spent.add(key);

      const records = spendRecords.get(key) ?? [];
      records.push({ fileName, inputIndex, txid });
      spendRecords.set(key, records);

      if (!outputs.has(key)) {
        if (isFundingOutpoint(prevTxid, input.outpointIndex)) {
          return;
        }
        unknownInputs.push({
          fileName,
          inputIndex,
          prevIndex: input.outpointIndex,
          prevTxid,
          txid,
        });
      }
    });
  }

  unknownInputs.sort((a, b) =>
    a.fileName === b.fileName
      ? a.inputIndex - b.inputIndex
      : a.fileName.localeCompare(b.fileName)
  );

  const unspentOutputs: UnspentOutputReport[] = [];
  for (const meta of outputs.values()) {
    const key = outpointKey(meta.txid, meta.vout);
    if (!spent.has(key)) {
      unspentOutputs.push({
        fileName: meta.fileName,
        lockingBytecodeHex: meta.lockingBytecodeHex,
        txid: meta.txid,
        valueSatoshis: meta.valueSatoshis.toString(),
        vout: meta.vout,
      });
    }
  }

  unspentOutputs.sort((a, b) =>
    a.fileName === b.fileName
      ? a.vout - b.vout
      : a.fileName.localeCompare(b.fileName)
  );

  const doubleSpends: DoubleSpend[] = [];
  for (const [key, references] of spendRecords.entries()) {
    if (references.length > 1) {
      const [outpointTxid, index] = key.split(':');
      doubleSpends.push({
        outpointTxid,
        outpointIndex: Number(index),
        referenceCount: references.length,
        references: references.sort((a, b) =>
          a.fileName === b.fileName
            ? a.inputIndex - b.inputIndex
            : a.fileName.localeCompare(b.fileName)
        ),
      });
    }
  }

  doubleSpends.sort((a, b) =>
    a.outpointTxid === b.outpointTxid
      ? a.outpointIndex - b.outpointIndex
      : a.outpointTxid.localeCompare(b.outpointTxid)
  );

  return { unknownInputs, unspentOutputs, doubleSpends };
};

const ensureTokenSetupUsesFunding = (tokenSetup: ParsedTransaction) => {
  const fundingTxid = getFundingInfo().txid;
  const spendsFunding = tokenSetup.transaction.inputs.some(
    (input) => binToHex(input.outpointTransactionHash) === fundingTxid
  );
  if (!spendsFunding) {
    throw new Error(
      `${tokenSetupFileName} must spend an output from funding-transaction.hex`
    );
  }
};

const orderTransactions = (
  transactions: ParsedTransaction[]
): ParsedTransaction[] => {
  const txById = new Map(transactions.map((tx) => [tx.txid, tx]));
  const dependencies = new Map<string, Set<string>>();
  const dependents = new Map<string, Set<string>>();

  for (const tx of transactions) {
    const deps = new Set<string>();
    tx.transaction.inputs.forEach((input) => {
      const prevTxid = binToHex(input.outpointTransactionHash);
      if (txById.has(prevTxid)) {
        deps.add(prevTxid);
        const refs = dependents.get(prevTxid) ?? new Set<string>();
        refs.add(tx.txid);
        dependents.set(prevTxid, refs);
      }
    });
    dependencies.set(tx.txid, deps);
    if (!dependents.has(tx.txid)) {
      dependents.set(tx.txid, new Set());
    }
  }

  const ready = transactions.filter(
    (tx) => (dependencies.get(tx.txid)?.size ?? 0) === 0
  );
  const ordered: ParsedTransaction[] = [];
  const priority = (fileName: string) =>
    fileName === tokenSetupFileName ? 0 : 1;
  const compare = (a: ParsedTransaction, b: ParsedTransaction) => {
    const diff = priority(a.fileName) - priority(b.fileName);
    return diff !== 0 ? diff : a.fileName.localeCompare(b.fileName);
  };

  while (ready.length > 0) {
    ready.sort(compare);
    const next = ready.shift();
    if (next === undefined) break;
    ordered.push(next);
    for (const dependentTxid of dependents.get(next.txid) ?? []) {
      const deps = dependencies.get(dependentTxid);
      if (deps === undefined) continue;
      deps.delete(next.txid);
      if (deps.size === 0) {
        const dependent = txById.get(dependentTxid);
        if (dependent !== undefined) ready.push(dependent);
      }
    }
  }

  if (ordered.length !== transactions.length) {
    throw new Error('Unable to order transactions without introducing cycles.');
  }

  if (ordered[0]?.fileName !== tokenSetupFileName) {
    throw new Error(
      `Broadcast order must begin with ${tokenSetupFileName}, but dependency analysis produced ${
        ordered[0]?.fileName ?? 'no transactions'
      }.`
    );
  }

  return ordered;
};

const createSendScript = (transactions: ParsedTransaction[]) => {
  const ordered = orderTransactions(transactions);
  const tokenSetup = ordered.find((tx) => tx.fileName === tokenSetupFileName);
  if (tokenSetup === undefined) {
    throw new Error(`Missing ${tokenSetupFileName} in the demo directory.`);
  }
  ensureTokenSetupUsesFunding(tokenSetup);
  const cliDefault = cliExampleCommand.replace(/ /g, '\\ ');
  const lines = [
    '#!/usr/bin/env bash',
    'set -euo pipefail',
    `CLI=\${CLI:-${cliDefault}}`,
    `# Example: CLI="${cliExampleCommand}"`,
    '',
    'send_tx() {',
    '  local file="$1"',
    '  local hex="$2"',
    '  echo "Sending $file..."',
    '  if output=$(printf \'%s\\n\' "$hex" | $CLI -stdin sendrawtransaction 2>&1); then',
    '    echo "  TXID: $output"',
    '    return 0',
    '  fi',
    '  if [[ "$output" == *"Missing inputs"* ]] || [[ "$output" == *"transaction already in block chain"* ]]; then',
    '    echo "  Skipping ($output)"',
    '    return 0',
    '  fi',
    '  echo "$output" >&2',
    '  return 1',
    '}',
    '',
  ];

  ordered.forEach((tx) => {
    lines.push(`send_tx "${tx.fileName}" "${tx.hex}"`);
    lines.push('');
  });

  return lines.join('\n').trimEnd();
};

const printReport = (report: Report) => {
  console.log('JSON Report:\n', JSON.stringify(report, null, 2));

  renderTable(
    'Unknown Inputs',
    [
      { header: 'File', getValue: (row) => row.fileName },
      { header: 'Input', getValue: (row) => row.inputIndex.toString() },
      { header: 'Prev TXID', getValue: (row) => row.prevTxid },
      { header: 'Prev Vout', getValue: (row) => row.prevIndex.toString() },
      { header: 'Spending TXID', getValue: (row) => row.txid },
    ],
    report.unknownInputs
  );

  renderTable(
    'Unspent Outputs',
    [
      { header: 'File', getValue: (row) => row.fileName },
      { header: 'Vout', getValue: (row) => row.vout.toString() },
      {
        header: 'Value (sats)',
        getValue: (row) => formatNumber(row.valueSatoshis),
      },
      { header: 'TXID', getValue: (row) => row.txid },
      {
        header: 'Locking Bytecode',
        getValue: (row) => row.lockingBytecodeHex,
      },
    ],
    report.unspentOutputs
  );

  renderTable(
    'Double Spends',
    [
      { header: 'Prev TXID', getValue: (row) => row.outpointTxid },
      { header: 'Prev Vout', getValue: (row) => row.outpointIndex.toString() },
      { header: 'Count', getValue: (row) => row.referenceCount.toString() },
      {
        header: 'References',
        getValue: (row) =>
          row.references
            .map(
              (reference) =>
                `${reference.fileName}#${reference.inputIndex} (${reference.txid})`
            )
            .join(', '),
      },
    ],
    report.doubleSpends
  );
};

try {
  const transactions = loadTransactions();
  if (process.argv.includes('--out')) {
    console.log(createSendScript(transactions));
  } else {
    const report = summarize(transactions);
    printReport(report);
    if (report.unknownInputs.length === 0 && report.doubleSpends.length === 0) {
      console.log(
        '\nReview passed. Run `bun run demo-review.ts --out > send.sh` to generate the broadcast script.'
      );
    }
  }
} catch (error) {
  console.error(error);
  process.exitCode = 1;
}
