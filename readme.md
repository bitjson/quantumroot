# Quantumroot: Quantum-Secure Vaults for Bitcoin Cash

Quantumroot is a quantum-secure Taproot. This repo contains a complete developer preview of a baseline contract implementation: a single-signer [`Quantumroot Schnorr+LM-OTS Vault](https://ide.bitauth.com/import-gist/60e779f718515b83fb80706e078acdb3).

The `Quantumroot Schnorr+LM-OTS Vault` is fully implemented in CashAssembly, including all private key derivation, address generation, and the quantum signing scheme. Wallets can compile transactions directly from the template using any HD Key – no template-specific code.

For more information, see the full Quantumroot post:

[Quantumroot: Quantum-Secure Vaults for Bitcoin Cash (bitjson.com) &rarr;](https://blog.bitjson.com/quantumroot)

---

## Example Transactions

For ease of review, this repo exports two example transactions, `Pre-Quantum Aggregation` and `Post-Quantum Aggregation`.

- The `Pre-Quantum Aggregation` transaction demonstrates the most privacy-preserving aggregation – Introspection-based **cross-input aggregation** – where all inputs spend UTXOs from the same address, i.e. no leaks of other wallet addresses.
- The `Post-Quantum Aggregation` transaction demonstrates both cross-input aggregation and a more specialized aggregation – CashToken-based **cross-address aggregation** – where UTXOs from multiple addresses are spent using the same quantum signature. (Strong privacy can still be achieved before and after such transactions, e.g. with ZKP covenants.)

### Pre-Quantum Aggregation

`Pre-Quantum Aggregation` spends 20 inputs:

- Input 0: a schnorr spend of Address A
- Input 1 through 19: introspection spends of Address A

### Post-Quantum Aggregation

`Post-Quantum Aggregation` spends 8 inputs. `Address Q` is a

- Input 0: includes the authorizing CashToken and quantum spend of Address Q
- Input 1: a token spend of Address A
- Input 2: a token spend of Address B
- Inputs 3 and 4: introspection spends of Address A
- Inputs 5 and 6: introspection spends of Address B
- Input 7: introspection spend of Address Q
