# Void-L1: A Proof-of-Ephemera Layer-1 Protocol

*Technical specification draft — v0.1*
*Written for review by protocol researchers familiar with stateless Ethereum, Verkle trees, history expiry, and L1 BFT consensus.*

---

## Abstract

Void-L1 is an experimental L1 protocol that synthesises four design choices that have been explored independently in the Ethereum research community — **statelessness, accumulator-based state commitments, reversible state expiry, and client-side anti-spam** — into a single coherent system. Validators retain only a compact accumulator root plus an active "hot set" of recently-touched objects; older state expires reversibly into a `GhostObject` form, recoverable through a bonded archive market.

We do not claim novelty in any individual primitive. Verkle trees (EIP-6800, Buterin/Kuszmaul), weak statelessness (Drake et al.), history expiry (EIP-4444), state rent proposals (Buterin 2018, EIP-2200 era discussions), KZG-based accumulators, and VDF-based anti-spam (Boneh/Wesolowski) are all prior art we draw on. Mina's recursive-SNARK constant-state design and Filecoin/Arweave's storage-market economics also overlap with our design space. Our contribution is the **specific synthesis** and a working Rust reference implementation (45+ purpose-built crates, 14-phase formal master plan).

This document describes the protocol, makes its security assumptions explicit, and **enumerates open problems we have not solved** — including BFT integration, the bootstrap economics of the archive market, and several light-client tradeoffs we believe deserve external review.

---

## 1. Motivation

The "stateless validator" research direction within the Ethereum community has been active since 2017 (Buterin's *State Size Management* post). The consensus problems it surfaces are well-known:

1. **Verkle trees** reduce witness sizes but require a hard fork and a multi-year state migration.
2. **History expiry (EIP-4444)** removes pre-merge historical blocks but keeps the active state set.
3. **Weak statelessness** lets validators verify without local state, but block proposers still need full state to construct witnesses.
4. **State rent** has been proposed multiple times (Buterin 2018, EIP-1077-adjacent discussions) and abandoned each time, primarily because of irreversible expiry semantics and user-experience concerns around losing access to balances.

Void-L1 explores a fresh design point. Rather than retrofitting these properties onto Ethereum's existing object model, we co-design the state commitment scheme, the transaction format, the expiry mechanism, and the recovery market from scratch in a system where all four can be assumed.

We do not believe this approach is *better* than retrofitting an existing chain. It is **different**, with different tradeoffs. The point of this document is to make those tradeoffs precise enough that protocol researchers can criticise them.

---

## 2. Notation and Preliminaries

We use the following throughout:

| Symbol | Meaning |
|---|---|
| `H(x)` | Domain-separated BLAKE3-256 hash of `x`. Each protocol context uses a distinct 32-byte domain prefix. |
| `Acc` | An *accumulator* — a binding cryptographic commitment to a set of objects supporting `commit`, `add`, `remove`, `prove_inclusion`, `verify_inclusion`. |
| `R_t` | The accumulator root at block height `t`. |
| `Ω` | The set of all currently-active objects (the "hot set"). |
| `O` | An object: `(id, owner, data, ttl_epoch)`. `id = H(domain, data)`. |
| `T` | A transaction: `(sender, intent, payload, witnesses, proofs, vdf_proof, sig, valid_until)`. |

All hashes are 32 bytes. All `u128` quantities (balances) are serialised as decimal strings on the wire to avoid JSON precision loss.

The reference implementation uses Ed25519 for signatures with domain separation `H(domain || message)` before signing — not raw `Ed25519(message)`. This is an explicit choice to prevent cross-protocol signature confusion (see §5.4).

---

## 3. State Model: Proof-of-Ephemera

### 3.1 Object lifecycle

Every object `O` carries a TTL epoch `O.ttl_epoch`. At each block, the state-rent enforcer classifies every active object:

```
classify(O, current_epoch) → Paid | Grace { remaining } | Prune
```

- `Paid`: rent for the current period has been paid; object stays active.
- `Grace`: rent is overdue but within the grace window (parameter `G`, currently 16 epochs).
- `Prune`: rent overdue past `G`; object transitions to `GhostObject` state.

A `GhostObject` is **not deleted** in the cryptographic sense — its commitment remains derivable from the accumulator history. It is removed from the active hot set, freeing validator memory, but a `ResurrectionTransition` can restore it by:

1. Providing a fresh `ArchiveProof` demonstrating the original bytes match the historical commitment.
2. Paying back-rent for all skipped periods plus a resurrection fee.

This is the key departure from prior state-rent proposals: **expiry is reversible**. Users who let an object expire can recover it by paying — they do not lose funds, they pay storage costs they should have paid earlier.

### 3.2 Accumulator structure

We use a layered accumulator design rather than a single global tree:

```
VoidStateCommitment_t = H(
    BalanceAccumulator_t,
    AssetRegistry_t,
    NftCollectionRoot_t,
    SmartAccountPolicyRoot_t,
    ValidatorCommitmentRoot_t,
)
```

The `BalanceAccumulator` is a sorted-leaf Merkle tree over `(account_id, asset_id, amount, frozen_flag)` tuples. We chose sorted-leaf Merkle over Verkle/KZG explicitly for the v0 implementation because:

1. **No trusted setup** — KZG requires a setup ceremony; we want to ship without one.
2. **Append-only-friendly** — most state changes are amount adjustments, not insertions; sorted-leaf Merkle handles this without re-sorting.
3. **Witness verifiability without precomputation** — light clients can verify with only the affected path.

We acknowledge this is suboptimal for proof size. Production deployments could swap in a Verkle backend behind the `Accumulator` trait (`crates/void-accumulator/src/`). The trait is intentionally narrow:

```rust
trait Accumulator {
    fn root(&self) -> Hash32;
    fn add(&mut self, leaf: Leaf) -> Result<(), Error>;
    fn remove(&mut self, leaf_id: &LeafId) -> Result<(), Error>;
    fn prove_inclusion(&self, leaf_id: &LeafId) -> Result<InclusionProof, Error>;
    fn verify_inclusion(root: &Hash32, leaf: &Leaf, proof: &InclusionProof) -> bool;
}
```

We've implemented two backends: `MerkleSetAccumulator` (sorted-leaf) and `MmrAccumulator` (Mountain Range, append-only). A Verkle backend is straightforward future work.

### 3.3 Versioned accumulators

Protocol upgrades — including swapping accumulator backends — are handled via `AccumulatorVersionRegistry` (`docs/adr/0009-versioned-accumulators.md`). It enforces:

- Monotone version tags.
- Retire-before-install: a version cannot be activated until the previous version is formally retired with a governance-bound migration commitment.
- Migrations must reference a passed governance decision; structurally, a `VersionMigration` cannot be constructed without a `DecisionOutcome::Accepted`.

This addresses what we see as the unsolved migration problem in stateless Ethereum: how to deploy a new accumulator scheme without forking off non-upgrading nodes. We replace "fork" with "governance-bound monotone version transition."

We acknowledge this concentrates a great deal of trust in governance. We do not have a satisfactory answer to "what if governance is captured?" beyond standard stake-weighting and slashing.

---

## 4. Transactions: Proof-Carrying Intents

### 4.1 Transaction structure

Every state-mutating transaction includes its own inclusion proofs against the most recent finalised root:

```rust
pub struct ProofCarryingTx {
    pub tx_id: TxId,                            // content-derived
    pub sender_commitment: Hash32,              // sender's identity_hash
    pub intent_type: IntentType,                // Transfer, AssetCreate, ...
    pub payload: Vec<u8>,                       // intent-specific bytes
    pub payload_commitment: Hash32,
    pub provided_witnesses: Vec<Witness>,
    pub accumulator_proofs: Vec<InclusionProof>,
    pub vdf_proof: VdfProof,                    // client-side anti-spam
    pub ttl_touch_policy: TtlTouchPolicy,
    pub fee_policy: Hash32,
    pub conflict_tags: Vec<ConflictTag>,        // for parallel scheduler
    pub valid_until_epoch: Epoch,
    pub signature_bundle: SignatureBundle,
    pub optional_commit_reveal: Option<CommitReveal>,
}
```

This is conceptually similar to:
- A ZK-rollup state-diff transaction (which carries proofs of the state it touches)
- Mina's transaction format (where everything is proof-carrying by virtue of recursive SNARKs)
- The "weak statelessness" witnesses Justin Drake described

We are not claiming originality. We are claiming **integration**: every intent type in the system is required to be proof-carrying, not just bridge or rollup transactions.

### 4.2 Verification cost

A stateless verifier with only `R_t` needs the following to validate a `Transfer`:

1. `verify_inclusion(R_t, sender_account_leaf, accumulator_proofs[0])` — one Merkle path verification (~log₂(N) hashes).
2. `verify_inclusion(R_t, recipient_account_leaf, accumulator_proofs[1])`.
3. `ed25519_verify(sender_pubkey, tx_id, signature)`.
4. `vdf_verify(vdf_proof, challenge_derived_from(sender, network_magic))`.
5. Balance arithmetic check (no underflow).
6. Nonce monotonicity check against the previously-applied nonce for `sender_commitment`.

Cost is bounded by `O(log N)` where `N` is the active state set, **not** by chain depth. This is the central performance claim.

### 4.3 Light client model

A light client tracks only `R_t` per block. To verify any transaction's effect, it requests the affected accumulator leaves + proofs from any full node (no trust required — the proofs are self-verifying against `R_t`).

This is similar to Ethereum's stateless-client proposal but applied uniformly to all transactions, not just rollup blocks.

---

## 5. Anti-Spam: Client-Side VDF

### 5.1 Mechanism

Every transaction must include `VdfProof { difficulty, final_state }` computed against:

```
challenge = H(VDF_CHALLENGE_DOMAIN, sender_identity_hash, 0u64, network_magic)
```

Difficulty is set by the `VdfDifficultyPolicy`:

```
required_difficulty = base
                    + (mempool_load_percent × per_load_factor)
                    - (reputation_bps × max_discount_bps / 10000)
                    , clamped to ceiling
```

`base = 1024` in our reference implementation. A modern CPU completes 1024 sequential BLAKE3 hashes in ~30ms.

### 5.2 Security argument

The VDF requirement is meant to bound the *rate* at which a single account can submit transactions, regardless of fee market state. An attacker willing to burn CPU can still spam, but their submission rate is capped by hardware. Mempool difficulty escalation ensures that as load increases, marginal spam becomes geometrically more expensive.

This is **not** a replacement for transaction fees. Fees serve a different purpose (allocating block space when supply < demand). The VDF prevents a degenerate state where the fee market collapses and an attacker free-rides on near-zero fees.

### 5.3 What this does not solve

- **VDF parallelism**: VDFs are by definition sequential, but an attacker can compute proofs for *many distinct accounts* in parallel. Per-account difficulty is therefore the meaningful bound.
- **VDF preprocessing**: an attacker with predictable target accounts can precompute proofs offline before a spam burst. We are interested in feedback on whether the challenge derivation should include a recent block hash to defeat this.
- **Light client interaction**: light clients verifying transactions must re-run the VDF verification (cheap — ~30µs) but cannot validate that the difficulty was *appropriate at the time*. Currently, they trust the inclusion in a finalised block as proxy. We see this as an open issue.

### 5.4 Signature domain separation

Every Ed25519 signature in the protocol is over `H(domain_tag, message)` rather than `message` directly. Each context (`TX_SIGN`, `BLOCK_PRODUCER_SIGN`, `VALIDATOR_IDENTITY`, etc.) has a distinct 32-byte domain. This prevents cross-protocol signature confusion attacks (e.g. tricking a wallet into signing a tx that's also valid as a block-producer signature).

Domain definitions are in `crates/void-crypto/src/domains.rs`.

---

## 6. Archive Market

### 6.1 Problem

If state can expire into `GhostObject` form, we need a mechanism for someone to:

1. **Hold** the original bytes long enough to allow resurrection requests.
2. **Serve** them on demand with cryptographic proof of correctness.
3. **Be punished** if they serve incorrect bytes.

### 6.2 Mechanism

Archive nodes (anyone with disk space and bandwidth) post offers:

```rust
pub struct ArchiveOffer {
    pub archive_node: ArchiveNodeId,
    pub object_commitment: Hash32,
    pub price_echo: u128,           // per retrieval
    pub bond_echo: u128,            // slashable on fraud
    pub deadline_epoch: Epoch,
    pub reputation_bps: u32,
}
```

A `RetrievalMarket::settle` pipeline executes one-shot:

1. **Expiry check**: offer must not have passed `deadline_epoch`.
2. **Misroute check**: offer must reference the requested `object_commitment`.
3. **Underpayment check**: payment ≥ price.
4. **Replay check**: settlement nullifier hasn't been used.
5. **Verify**: archive provides `RetrievalProof { receipt, payload, witness }`. We recompute `commitment(payload) == object_commitment`. If mismatch, the bond is slashed.

`SettlementOutcome` is pinned wire-tags `Paid = 1` / `Slashed = 2`. Settlement commits to `(offer, object, archive, paid, outcome, resolution)` under `HashDomain::ARCHIVE_SETTLEMENT`.

### 6.3 Open economic questions

- **Bootstrap**: in early epochs, who archives? Treasury-funded subsidies are the obvious answer but introduce centralisation pressure. We have not solved this.
- **Bond sizing**: what bond size makes fraud unprofitable? Depends on the marginal value of the archived object to its owner. We have no satisfactory general answer.
- **Whitewash attacks**: an archive can serve correct bytes 999 times to build reputation, then defraud on the 1000th high-value request. Reputation systems alone don't solve this. Slashing helps but the bond must exceed the expected fraud profit.

These resemble (and we believe overlap with) problems in Filecoin's design space. We do not claim to have improved on the storage-market literature.

---

## 7. Consensus

We use a simple wall-clock round-robin leader election in the current reference implementation:

```
proposer_at(epoch_n) = validators_sorted_by_pubkey[epoch_n mod N]
```

This is **not** production-grade and we know it. Real BFT consensus is on the explicit gap list. The `void-consensus` and `void-finality` crates already contain a working reference implementation of HotStuff-style 3-phase commit (`BftRound`, ≥⅔ quorum → `FinalityCertificate`), but it is not yet wired into the live run-loop.

What works today across multiple nodes:
- Deterministic block production with cross-node ledger parity (verified end-to-end).
- Mempool gossip with replay-protection-aware deduplication.
- Per-account nonce enforcement that survives node restarts.

What does not work:
- Liveness under arbitrary validator failures (a missed slot waits 5 seconds for the next).
- Fast finality (current "finality" = 1 block depth; production needs proper BFT confirmation).
- Slashing of byzantine behaviour (`SlashableFault` types exist; runtime integration does not).

We invite review on whether HotStuff is the right choice here, vs Tendermint, vs Single Slot Finality research (Buterin's recent posts), vs more exotic designs (Whisk's single secret leader election to mitigate MEV).

---

## 8. Tokenomics

Brief, because we expect researchers will mostly skip this section.

- Native asset `$VOID`, hard cap `100,000,000` units (enforced at protocol level via `EmissionLedger::try_emit`).
- Halving emission curve with closed-form `cumulative_through(n)`; total issuance mathematically bounded.
- No premine.
- Three value flows: block emission to validators (cap-gated), transaction fees to producer, state rent burned or directed by governance.
- Stake-weighted on-chain governance via `void-governance` with five proposal kinds.

The economic design is intentionally conservative. We do not have novel mechanism design here.

---

## 9. Comparison to Related Work

We attempt to be specific.

| | Void-L1 | Verkle Ethereum (proposed) | Mina | Stateless Eth (research) |
|---|---|---|---|---|
| State commitment | Layered Merkle + accumulator versioning | Verkle tree | Recursive SNARK | Verkle tree |
| Validator state | Hot set + roots | Verkle tree state | ~22 KB constant | Stateless (verifies witnesses) |
| Tx carries proof | Required for all intents | Block-level witness | Inherent (SNARK) | Block-level witness |
| State expiry | Reversible (GhostObject) | History only (EIP-4444) | N/A (constant state) | Not addressed |
| Trusted setup | None | Required (Verkle) | Required (SNARK) | Required (Verkle) |
| Anti-spam | Client-side VDF + fee | Fee only | Fee only | Fee only |
| Status | Working multi-node devnet | Multi-year migration | Live mainnet | Research |

**Honest assessment**: Mina has shipped a more radical form of statelessness than we plan to. Our advantage over Mina is that we don't require a SNARK trusted setup or per-tx SNARK proving. Our disadvantage is significantly larger validator state than Mina's 22 KB.

Compared to Verkle Ethereum: we trade migration risk for greenfield design risk. Whether that trade is good depends on what you weight more.

---

## 10. Open Problems We Want Review On

We list these explicitly because we believe acknowledging them is more useful than hiding them.

1. **Accumulator scheme choice**. Sorted-leaf Merkle is fine for v0 but suboptimal. Should we move to Verkle (trusted setup), KZG vector commitments (also setup), or a different no-setup scheme like RSA accumulators (large primes, expensive)?
2. **VDF challenge derivation**. Should it bind to recent block hash to prevent precomputation attacks? At what depth?
3. **Archive market bootstrap**. The mechanism works once participants exist; we have no satisfying answer to "how does the market form in epoch 1?"
4. **Reversible expiry vs hard expiry**. We chose reversible because UX is better, but it complicates accumulator versioning (a resurrected object must be re-added under the *current* accumulator scheme, not its original one). Is this complexity worth the UX win?
5. **BFT integration**. HotStuff is the obvious choice but Single Slot Finality research is moving fast. What would we miss by committing to HotStuff now?
6. **Slashing for liveness vs safety faults**. We have separable fault types but no analysis of optimal penalty schedules. The literature here is sparse.
7. **MEV resistance**. The fair-ordering layer uses `H(seed || tx_id)` for tie-breaks. We have not analysed this against an adversary who can withhold and selectively release transactions. Whisk-style single secret leader election would help; we haven't implemented it.

---

## 11. What We've Built

This is engineering status, not a pitch. A reader interested in evaluating the design should know:

- 45+ Rust crates, ~150K LOC.
- 14-phase formal master plan; every phase has property tests, specs in `docs/specs/`, ADRs in `docs/adr/`.
- All cryptographic primitives implemented and unit-tested (Ed25519 with domain separation, BLAKE3-domain hashes, MMR + sorted-leaf accumulators, prototype VDF).
- Working multi-validator devnet with cross-node ledger parity, mempool gossip, replay protection, transaction fees, browser explorer.
- No external cryptography audit yet. Crypto security gate documented in `docs/specs/crypto-security-gate-v0.md`.

We do not have:
- A SNARK-friendly accumulator (deliberate v0 choice).
- Production BFT consensus.
- libp2p (currently HTTP polling between nodes).
- A wasmer/wasmtime adapter (we have a `Vm` trait and a 14-opcode reference interpreter).

---

## 12. Why Publish This

We are aware that the L1 space is saturated with low-quality projects. We publish this hoping for either:

- **Pointed criticism**: "this scheme breaks under X attack", "your accumulator choice is wrong because Y", "your VDF analysis ignores Z". This is genuinely the most valuable response.
- **Pointers to prior art** we missed: if some primitive is older or better than we know, please tell us.
- **Confirmation** that the synthesis is at least coherent, even if every individual choice is debatable.

We are explicitly **not** asking for an endorsement, a tweet, or any kind of social signal. We are asking for technical review by people who think about these problems professionally.

---

## 13. References

Primary inspirations and prior art we draw on:

- Buterin, V. *State Size Management*. 2017.
- Buterin, V. *Verkle Trees*. 2021.
- Drake, J. *Stateless Ethereum*. ethresear.ch series, 2019–2024.
- EIP-4444: *Bound Historical Data in Execution Clients*.
- EIP-6800: *Verkle Tree State*.
- Boneh, D., Bonneau, J., Bünz, B., Fisch, B. *Verifiable Delay Functions*. CRYPTO 2018.
- Wesolowski, B. *Efficient Verifiable Delay Functions*. EUROCRYPT 2019.
- Yin, M. et al. *HotStuff: BFT Consensus with Linearity and Responsiveness*. PODC 2019.
- Mina Protocol whitepaper.
- Filecoin protocol specification.
- Buterin, V. *Single Slot Finality* discussion posts. 2023–2024.
- Buterin, V. *Whisk: A Practical Shuffle-Based SSLE Protocol*. 2022.

Repository: source available on request to reviewers.

---

*Document prepared for technical review. Constructive criticism welcomed at any level of detail.*

*Void-L1 reference implementation — May 2026.*
