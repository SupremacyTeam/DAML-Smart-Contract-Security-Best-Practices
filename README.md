<div align="center">
  <img src="./Supremacy.svg" style="margin: 0 auto 100px; width: 400px;" />
  <!-- <h1>Supremacy</h1> -->
  <h4 align="center">
    DAML Smart Contract Security Best Practices
  </h4>
  <p>
    <a href="https://x.com/SupremacyHQ"><img alt="X Follow" src="https://img.shields.io/twitter/url.svg?style=social&label=Follow%20%40SupremacyHQ&url=https%3A%2F%2Fx.com%2FSupremacyHQ"></a>
</a>
  </p>
</div>

-   [Common pitfalls of DAML smart contracts](#common-pitfalls-of-daml-smart-contracts)
    -   [Overly permissive choice controllers](#overly-permissive-choice-controllers)
    -   [Missing signatory authorization on contract creation](#missing-signatory-authorization-on-contract-creation)
    -   [Unintended observer exposure (privacy leakage)](#unintended-observer-exposure-privacy-leakage)
    -   [Unsafe contract key uniqueness assumptions](#unsafe-contract-key-uniqueness-assumptions)
    -   [Missing ensure precondition checks](#missing-ensure-precondition-checks)
    -   [Arithmetic logic errors in governance or financial calculations](#arithmetic-logic-errors-in-governance-or-financial-calculations)
    -   [Division by zero in Decimal calculations](#division-by-zero-in-decimal-calculations)
    -   [Time-of-check to time-of-use with getTime](#time-of-check-to-time-of-use-with-gettime)
    -   [Consuming choice used where nonconsuming is intended](#consuming-choice-used-where-nonconsuming-is-intended)
    -   [Unchecked archive leading to asset destruction](#unchecked-archive-leading-to-asset-destruction)
    -   [Unrestricted delegation chains](#unrestricted-delegation-chains)
    -   [Missing error handling on lookupByKey](#missing-error-handling-on-lookupbykey)
-   [DAML-specific design pattern attacks](#daml-specific-design-pattern-attacks)
    -   [Authority smuggling via flexible controllers](#authority-smuggling-via-flexible-controllers)
    -   [Contract key collision abuse](#contract-key-collision-abuse)
    -   [Signatory bait: tricking parties into becoming signatories](#signatory-bait-tricking-parties-into-becoming-signatories)
    -   [Separation of duties violation via controller reassignment](#separation-of-duties-violation-via-controller-reassignment)
    -   [Stale contract reference exploitation](#stale-contract-reference-exploitation)
    -   [Upgrade mechanism hijacking](#upgrade-mechanism-hijacking)
    -   [Denial-of-service via choice spam](#denial-of-service-via-choice-spam)
    -   [Privacy inference via transaction timing](#privacy-inference-via-transaction-timing)
-   [Case Analysis](#case-analysis)
    -   [Incorrect controller allows unauthorized token transfer](#incorrect-controller-allows-unauthorized-token-transfer)
    -   [Privacy leakage through overly broad observer lists](#privacy-leakage-through-overly-broad-observer-lists)
    -   [Contract key race condition in concurrent submissions](#contract-key-race-condition-in-concurrent-submissions)
-   [Recommended Tooling and Practices](#recommended-tooling-and-practices)

----------

> **Note on DAML's security model:** DAML (Daml) is a purpose-built smart contract language for multi-party workflows on the Canton protocol. Unlike Solidity/EVM or Rust/Solana, DAML provides several security properties **by design**: reentrancy is impossible (the execution model is deterministic and sequential), integer overflow/underflow is caught at runtime with safe arithmetic, and authorization is enforced declaratively via signatories and controllers rather than ad-hoc programmatic checks. This document focuses on the **remaining** classes of vulnerabilities that DAML developers must still guard against.

----------

## Common pitfalls of DAML smart contracts

### Overly permissive choice controllers

-   **Severity:** High
-   **Description:** In DAML, a `controller` clause determines which party can exercise a choice. If the controller is set to a party field that any user can influence (e.g., passed as a choice argument rather than derived from the contract's signatories), an unauthorized party may be able to exercise a privileged action.
-   **Exploit Scenario:**

```haskell
template Vault with
    owner : Party
    custodian : Party
    balance : Decimal
  where
    signatory custodian
    observer owner

    -- INSECURE: anyone who knows the contract can call Withdraw
    -- by passing themselves as 'requestor'
    choice Withdraw : ContractId Vault
      with
        requestor : Party
        amount : Decimal
      controller requestor
      do
        create this with balance = balance - amount

```

Any party with visibility into this contract (e.g., the `custodian`, who is a signatory) can exercise `Withdraw` by passing themselves as `requestor`, draining the vault without the `owner`'s consent. Note: in DAML, a party must be able to _see_ a contract to exercise a choice on it — but this visibility requirement should never be relied upon as a security control.

-   **Recommendation:** Hardcode the controller to a known, trusted party field from the contract payload. Never derive controllers from choice arguments.

```haskell
template Vault with
    owner : Party
    custodian : Party
    balance : Decimal
  where
    signatory custodian
    observer owner

    choice Withdraw : ContractId Vault
      with
        amount : Decimal
      controller owner  -- Only the owner can withdraw
      do
        assert (amount > 0.0)
        assert (amount <= balance)
        create this with balance = balance - amount

```

### Missing signatory authorization on contract creation

-   **Severity:** High
-   **Description:** DAML requires that all signatories authorize the creation of a contract. However, a poorly designed workflow may allow a party to create a contract that names another party as signatory without that party's genuine consent—typically by exercising a choice that already carries the signatory's authority from a parent contract. If the parent contract's authority is too broad, one party can unilaterally bind another.
-   **Exploit Scenario:**

```haskell
template MasterAgreement with
    partyA : Party
    partyB : Party
  where
    signatory partyA, partyB

    -- INSECURE: partyA alone can create obligations for partyB
    choice CreateObligation : ContractId Obligation
      with
        amount : Decimal
      controller partyA
      do
        create Obligation with debtor = partyB; creditor = partyA; amount

template Obligation with
    debtor : Party
    creditor : Party
    amount : Decimal
  where
    signatory creditor, debtor

```

Party A can unilaterally create arbitrary `Obligation` contracts binding Party B, because the `MasterAgreement` choice body inherits both signatories' authorization.

-   **Recommendation:** Use a propose-accept (multi-step) pattern so that both parties explicitly consent to new obligations.

```haskell
template ObligationProposal with
    debtor : Party
    creditor : Party
    amount : Decimal
  where
    signatory creditor
    observer debtor

    choice AcceptObligation : ContractId Obligation
      controller debtor
      do
        create Obligation with debtor; creditor; amount

    choice RejectObligation : ()
      controller debtor
      do
        return ()

template Obligation with
    debtor : Party
    creditor : Party
    amount : Decimal
  where
    signatory creditor, debtor

```

### Unintended observer exposure (privacy leakage)

-   **Severity:** High
-   **Description:** Observers in DAML can see the full contract payload. Adding parties as observers without careful consideration leaks confidential data (prices, amounts, counterparty identities) to parties who should not see it. This is particularly dangerous in regulated environments (e.g., GDPR, financial privacy).
-   **Exploit Scenario:**

```haskell
template Trade with
    buyer : Party
    seller : Party
    price : Decimal
    regulator : Party
    allParticipants : [Party]  -- includes unrelated market participants
  where
    signatory buyer, seller
    observer regulator :: allParticipants
    -- All participants can see the exact trade price and counterparties

```

Every party in `allParticipants` gains visibility into the trade details, including sensitive pricing information.

-   **Recommendation:** Apply the principle of least privilege for observers. Only add parties who strictly need visibility. Use separate summary contracts for regulatory reporting that strip sensitive fields.

```haskell
template Trade with
    buyer : Party
    seller : Party
    price : Decimal
    regulator : Party
  where
    signatory buyer, seller
    observer regulator  -- Only the regulator observes; no broadcast list

template TradeConfirmation with
    tradeId : Text
    buyer : Party
    seller : Party
    regulator : Party
  where
    signatory regulator
    observer buyer, seller
    -- No price field exposed in the confirmation

```

### Unsafe contract key uniqueness assumptions

-   **Severity:** High
-   **Description:** In Canton, contract key uniqueness is **not globally enforced** across concurrent submissions. Two transactions submitted concurrently may both succeed in creating contracts with the same key, violating uniqueness assumptions. Code that relies on `lookupByKey` returning `None` to guarantee uniqueness can exhibit race conditions.
-   **Exploit Scenario:**

```haskell
template Account with
    owner : Party
    accountId : Text
    balance : Decimal
  where
    signatory owner
    key (owner, accountId) : (Party, Text)
    maintainer key._1

    nonconsuming choice OpenSubAccount : ContractId Account
      with
        subId : Text
      controller owner
      do
        optCid <- lookupByKey @Account (owner, subId)
        case optCid of
          None -> create Account with owner; accountId = subId; balance = 0.0
          Some _ -> abort "Account already exists"

```

If two `OpenSubAccount` commands are submitted concurrently with the same `subId`, both may observe `None` from `lookupByKey` and both may succeed, creating duplicate accounts.

-   **Recommendation:** Use the consuming `Generator` pattern to serialize key creation through a single active contract, ensuring at most one concurrent command can succeed.

```haskell
template AccountGenerator with
    owner : Party
  where
    signatory owner

    choice GenerateAccount : (ContractId AccountGenerator, ContractId Account)
      with
        subId : Text
      controller owner
      do
        optCid <- lookupByKey @Account (owner, subId)
        case optCid of
          None -> do
            accCid <- create Account with owner; accountId = subId; balance = 0.0
            genCid <- create this
            return (genCid, accCid)
          Some cid -> do
            genCid <- create this
            abort "Account already exists"

```

Since `GenerateAccount` is a consuming choice, concurrent submissions will contend on the `AccountGenerator` contract, and at most one will succeed per ledger effective time.

### Missing ensure precondition checks

-   **Severity:** Medium
-   **Description:** DAML's `ensure` keyword enforces invariants at contract creation time. Omitting `ensure` clauses allows the creation of contracts with invalid state (e.g., negative balances, empty party lists, zero amounts), which can corrupt downstream business logic.
-   **Exploit Scenario:**

```haskell
template Loan with
    borrower : Party
    lender : Party
    principal : Decimal
    interestRate : Decimal
  where
    signatory lender, borrower
    -- No 'ensure' block; a loan with negative principal or rate > 1.0 can be created

```

A malicious party could propose a loan with `principal = -1000.0`, causing downstream repayment logic to transfer funds in the wrong direction.

-   **Recommendation:** Always add `ensure` clauses to validate all business-critical invariants at contract creation.

```haskell
template Loan with
    borrower : Party
    lender : Party
    principal : Decimal
    interestRate : Decimal
  where
    signatory lender, borrower
    ensure principal > 0.0
        && interestRate >= 0.0
        && interestRate <= 1.0
        && borrower /= lender

```

### Arithmetic logic errors in governance or financial calculations

-   **Severity:** High
-   **Description:** While DAML uses arbitrary-precision `Decimal` (10 decimal places) and safe `Int` arithmetic by default (no silent overflow), developers can still introduce logic errors: incorrect order of operations, rounding at the wrong stage, or truncation when converting between types. These errors are especially dangerous in voting thresholds, fee calculations, and pro-rata distributions.
-   **Exploit Scenario:**

```haskell
-- INSECURE: integer division truncates before multiplication
calculateShare : Int -> Int -> Int -> Int
calculateShare total userStake poolSize =
    (userStake / poolSize) * total
    -- If userStake = 1, poolSize = 3, total = 900
    -- Result: (1 / 3) * 900 = 0 * 900 = 0  (expected: 300)

```

-   **Recommendation:** Perform multiplications before divisions to preserve precision. Use `Decimal` types for financial calculations rather than `Int`.

```haskell
calculateShare : Decimal -> Decimal -> Decimal -> Decimal
calculateShare total userStake poolSize =
    (userStake * total) / poolSize
    -- Result: (1.0 * 900.0) / 3.0 = 300.0

```

### Division by zero in Decimal calculations

-   **Severity:** High
-   **Description:** Division by zero in DAML aborts the transaction at runtime. If a divisor is derived from contract state or user input and is not validated, an attacker or erroneous state can cause critical choices to permanently fail.
-   **Exploit Scenario:**

```haskell
choice DistributeRewards : ()
  with
    totalReward : Decimal
  controller admin
  do
    members <- fetchMemberCount  -- could return 0 if all members left
    let perMember = totalReward / intToDecimal members
    -- Aborts if members == 0
    forA_ memberList (\m -> createReward m perMember)

```

-   **Recommendation:** Always validate divisors before performing division.

```haskell
choice DistributeRewards : ()
  with
    totalReward : Decimal
  controller admin
  do
    members <- fetchMemberCount
    assertMsg "No members to distribute to" (members > 0)
    let perMember = totalReward / intToDecimal members
    forA_ memberList (\m -> createReward m perMember)

```

### Time-of-check to time-of-use with getTime

-   **Severity:** Medium
-   **Description:** `getTime` in DAML returns the ledger effective time of the transaction, which is chosen by the submitter within a configurable skew window. An attacker can manipulate the submission time (within bounds) to bypass time-based access controls or exploit time-dependent pricing.
-   **Exploit Scenario:**

```haskell
choice ClaimBonus : ContractId Payout
  controller employee
  do
    now <- getTime
    assert (now >= bonusWindowStart && now <= bonusWindowEnd)
    create Payout with recipient = employee; amount = bonusAmount

```

If the ledger time skew tolerance is large, an employee could submit a claim after the bonus window has objectively closed by setting the ledger effective time to a value within the window.

-   **Recommendation:** Configure the domain's maximum ledger time skew to the tightest tolerance acceptable for your use case. For high-value time-sensitive operations, use short skew windows and consider additional off-ledger time attestation.

```haskell
-- At the application level, configure Canton's time model:
-- canton.parameters.ledger-time-record-time-tolerance = 1s

-- In the contract, combine with additional checks:
choice ClaimBonus : ContractId Payout
  controller employee
  do
    now <- getTime
    assertMsg "Bonus window not open" (now >= bonusWindowStart)
    assertMsg "Bonus window has closed" (now <= bonusWindowEnd)
    -- Short skew tolerance ensures 'now' closely tracks real wall-clock time
    create Payout with recipient = employee; amount = bonusAmount

```

### Consuming choice used where nonconsuming is intended

-   **Severity:** Medium
-   **Description:** By default, choices in DAML are consuming — they archive the contract upon exercise. If a developer forgets to mark a read-only or query choice as `nonconsuming`, exercising it will destroy the contract, causing loss of state and denial-of-service for other parties.
-   **Exploit Scenario:**

```haskell
template Registry with
    admin : Party
    entries : [(Text, Party)]
  where
    signatory admin

    -- INSECURE: querying the registry destroys it
    choice LookupEntry : Optional Party
      with
        name : Text
      controller admin
      do
        return (lookup name entries)

```

Any call to `LookupEntry` archives the `Registry` contract, destroying the entire registry.

-   **Recommendation:** Explicitly mark read-only choices as `nonconsuming`.

```haskell
template Registry with
    admin : Party
    entries : [(Text, Party)]
  where
    signatory admin

    nonconsuming choice LookupEntry : Optional Party
      with
        name : Text
      controller admin
      do
        return (lookup name entries)

```

### Unchecked archive leading to asset destruction

-   **Severity:** High
-   **Description:** When a choice body exercises another contract (e.g., via `exercise` or `archive`), it can destroy assets if the choice body does not properly recreate or transfer them. Unlike EVM where tokens persist in storage, DAML contracts are immutable and consumed — archiving is permanent unless a new contract is created.
-   **Exploit Scenario:**

```haskell
choice SettleTrade : ()
  controller buyer
  do
    exercise assetCid Archive  -- Asset is gone
    -- BUG: forgot to create a new Asset for the buyer
    return ()

```

The asset is permanently destroyed with no replacement created.

-   **Recommendation:** Always pair archive operations with explicit creation of replacement contracts. Use DAML's type system to enforce that choices return the newly created `ContractId`.

```haskell
choice SettleTrade : ContractId Asset
  controller buyer
  do
    asset <- fetch assetCid
    exercise assetCid Archive
    create asset with owner = buyer  -- Explicitly transfer ownership

```

### Unrestricted delegation chains

-   **Severity:** Medium
-   **Description:** DAML's authorization model allows choices to create new contracts that carry signatories' authority. If delegation is implemented without bounds, a delegated party can recursively create sub-delegations, potentially granting authority to untrusted parties several levels deep.
-   **Exploit Scenario:**

```haskell
template DelegatedRight with
    owner : Party
    delegate : Party
  where
    signatory owner
    observer delegate

    choice SubDelegate : ContractId DelegatedRight
      with
        newDelegate : Party
      controller delegate
      do
        -- delegate can pass authority to anyone, indefinitely
        create DelegatedRight with owner; delegate = newDelegate

```

-   **Recommendation:** Add a `maxDepth` field or restrict sub-delegation to an explicit allowlist. Enforce the bound in the choice body.

```haskell
template DelegatedRight with
    owner : Party
    delegate : Party
    remainingDepth : Int
  where
    signatory owner
    observer delegate
    ensure remainingDepth >= 0

    choice SubDelegate : ContractId DelegatedRight
      with
        newDelegate : Party
      controller delegate
      do
        assertMsg "Delegation depth exceeded" (remainingDepth > 0)
        create DelegatedRight with
          owner
          delegate = newDelegate
          remainingDepth = remainingDepth - 1

```

### Missing error handling on lookupByKey

-   **Severity:** Medium
-   **Description:** `lookupByKey` returns `Optional (ContractId a)`. Developers sometimes use `fromSome` or pattern match only the `Some` case, causing the transaction to abort unexpectedly when the key does not exist. In worst cases this can be weaponized by an adversary who archives a keyed contract to cause dependent transactions to fail.
-   **Exploit Scenario:**

```haskell
choice TransferToAccount : ContractId Asset
  controller sender
  do
    (targetCid, _) <- fetchByKey @Account (receiver, accountId)
    -- Aborts if no Account exists for receiver, blocking the entire transaction
    exercise targetCid Deposit with asset = self

```

If the target `Account` contract is archived through normal business operations (or by a signatory exercising the `Archive` choice), the sender's transaction will abort. In concurrent multi-party workflows, this race condition can cause critical transfers to fail unpredictably.

-   **Recommendation:** Use `lookupByKey` with explicit handling of both `Some` and `None` branches, and design for graceful degradation.

```haskell
choice TransferToAccount : Either Text (ContractId Asset)
  controller sender
  do
    optCid <- lookupByKey @Account (receiver, accountId)
    case optCid of
      Some targetCid -> do
        exercise targetCid Deposit with asset = self
        return (Right self)
      None ->
        return (Left "Receiver account not found; transfer not executed")

```

----------

## DAML-specific design pattern attacks

### Authority smuggling via flexible controllers

-   **Severity:** High
-   **Description:** In DAML, within a choice body, the executing code has the combined authorization of the contract's signatories and the choice's controllers. An attacker may exploit this by getting a legitimately authorized party to exercise a choice whose body creates contracts or exercises other choices that exceed what the controller intended to authorize.
-   **Exploit Scenario:**

```haskell
template Treasury with
    admin : Party
    operator : Party
  where
    signatory admin

    choice RoutineAudit : ContractId Treasury
      controller operator
      do
        -- Appears benign, but within this body we have admin's authority.
        -- A malicious or negligent template designer could include:
        create IOU with issuer = admin; owner = operator; amount = 1000000.0
        create this

```

The `operator` exercises `RoutineAudit`, and within the choice body, the code runs with `admin`'s signatory authority (inherited from the `Treasury` contract's signatory list), allowing creation of an `IOU` signed by `admin`. Note: DAML templates are immutable once deployed — this vulnerability arises at **template design time**, not at runtime. The risk is that a template author (malicious or negligent) embeds excessive high-authority operations inside a choice controllable by a lower-privilege party.

-   **Recommendation:** Limit what each choice body can do. Keep high-authority choices minimal. Audit every `create` and `exercise` call within choice bodies to confirm the action is intended by all authorizing parties. Consider using interface-based patterns to separate high- and low-privilege operations.

```haskell
template Treasury with
    admin : Party
    operator : Party
  where
    signatory admin
    observer operator

    -- Minimal choice: only returns audit data, creates nothing
    nonconsuming choice RoutineAudit : AuditReport
      controller operator
      do
        now <- getTime
        return AuditReport with timestamp = now; auditor = operator

    -- High-privilege choice requires admin
    choice MintIOU : ContractId IOU
      with
        owner : Party
        amount : Decimal
      controller admin
      do
        create IOU with issuer = admin; owner; amount

```

### Contract key collision abuse

-   **Severity:** High
-   **Description:** Since Canton does not guarantee global contract key uniqueness under concurrent submissions, a malicious party who is a key maintainer can intentionally create duplicate-keyed contracts to confuse downstream workflows that assume uniqueness.
-   **Exploit Scenario:**

A malicious maintainer submits multiple concurrent transactions, each creating a `Token` contract with the same key. Downstream `fetchByKey` calls may return different contract IDs at different times, leading to inconsistent state.

-   **Recommendation:** Use the consuming `Generator` pattern (described above) to serialize key creation. Never trust that `lookupByKey` returning `None` in Canton guarantees global absence. For critical uniqueness requirements, implement application-level deduplication or use command deduplication features of the Ledger API.

### Signatory bait: tricking parties into becoming signatories

-   **Severity:** High
-   **Description:** A contract's signatories are bound by all choices on that contract. A malicious designer can create a contract template where a party becomes a signatory (through a seemingly benign acceptance) but the template contains choices that allow the other signatory to unilaterally perform harmful actions with the victim's authority.
-   **Exploit Scenario:**

```haskell
template Partnership with
    partyA : Party
    partyB : Party
  where
    signatory partyA, partyB

    -- partyA can unilaterally issue debt in partyB's name
    choice IssueBond : ContractId Bond
      with
        amount : Decimal
      controller partyA
      do
        create Bond with issuer = partyB; holder = partyA; faceValue = amount

```

Party B agrees to a "Partnership" but unknowingly authorizes Party A to issue bonds in Party B's name.

-   **Recommendation:** Parties must audit all choices on a template before consenting to become signatories. Template designers should limit the scope of actions available through choices and use the propose-accept pattern to require explicit consent for each high-impact action.

```haskell
template Partnership with
    partyA : Party
    partyB : Party
  where
    signatory partyA, partyB

    -- Bond issuance requires BOTH parties to act
    choice ProposeIssueBond : ContractId BondProposal
      with
        amount : Decimal
      controller partyA
      do
        create BondProposal with partyA; partyB; amount

template BondProposal with
    partyA : Party
    partyB : Party
    amount : Decimal
  where
    signatory partyA
    observer partyB

    choice ApproveBond : ContractId Bond
      controller partyB
      do
        create Bond with issuer = partyB; holder = partyA; faceValue = amount

```

### Separation of duties violation via controller reassignment

-   **Severity:** Medium
-   **Description:** Observers have read-only access to contracts. However, if a choice allows a controller to reassign a privileged role (e.g., an approver) to any arbitrary party, the controller can collude with an observer or other party to bypass intended approval workflows. This is a separation-of-duties violation: the party who creates proposals should not be the party who controls who approves them.
-   **Exploit Scenario:**

```haskell
template Proposal with
    proposer : Party
    approver : Party
    observers : [Party]
  where
    signatory proposer
    observer approver :: observers

    choice Reassign : ContractId Proposal
      with
        newApprover : Party
      controller proposer
      do
        -- BUG: proposer can set any observer as the approver
        create this with approver = newApprover

```

The proposer can set a colluding observer as the new approver, allowing the observer to approve their own proposals.

-   **Recommendation:** Validate that the `newApprover` is not in the observer list, or restrict reassignment to an enumerated set of authorized approvers.

```haskell
    choice Reassign : ContractId Proposal
      with
        newApprover : Party
      controller proposer
      do
        assertMsg "Approver cannot be an observer"
          (newApprover `notElem` observers)
        assertMsg "Approver cannot be the proposer"
          (newApprover /= proposer)
        create this with approver = newApprover

```

### Stale contract reference exploitation

-   **Severity:** Medium
-   **Description:** In DAML, a `ContractId` can become stale if the referenced contract is archived between the time the ID was obtained and the time it is used. Storing `ContractId` values in long-lived contracts creates a risk that the reference points to an archived (non-existent) contract, causing runtime failures or, worse, allowing an attacker to archive the target contract and replace it with a different one sharing the same key.
-   **Exploit Scenario:**

```haskell
template Escrow with
    buyer : Party
    seller : Party
    assetCid : ContractId Asset  -- stored ContractId; may become stale
  where
    signatory buyer, seller

    choice Release : ContractId Asset
      controller buyer
      do
        exercise assetCid TransferTo with newOwner = seller
        -- Fails if assetCid has been archived

```

-   **Recommendation:** Prefer contract keys over stored `ContractId` values for cross-contract references. When keys are not possible, design workflows to fetch and validate the referenced contract within the same transaction.

```haskell
template Escrow with
    buyer : Party
    seller : Party
    assetKey : (Party, Text)  -- Reference by key, not ContractId
  where
    signatory buyer, seller

    choice Release : ContractId Asset
      controller buyer
      do
        (assetCid, asset) <- fetchByKey @Asset assetKey
        assertMsg "Asset owner mismatch" (asset.owner == buyer)
        exercise assetCid TransferTo with newOwner = seller

```

### Upgrade mechanism hijacking

-   **Severity:** High
-   **Description:** DAML contracts are immutable once deployed. Upgrade workflows typically involve exercising a choice on the old contract that archives it and creates a new contract from an updated template. If the upgrade choice does not properly validate who can trigger it or what the new template version contains, a malicious party can hijack the upgrade to change terms in their favor.
-   **Exploit Scenario:**

```haskell
template TokenV1 with
    issuer : Party
    holder : Party
    amount : Decimal
  where
    signatory issuer, holder

    choice Upgrade : ContractId TokenV2
      controller issuer  -- Only issuer controls upgrade
      do
        -- issuer can change terms unilaterally during upgrade
        create TokenV2 with issuer; holder; amount; fee = 0.5

```

The issuer upgrades the token and adds a `fee` field that the holder never consented to.

-   **Recommendation:** Require both signatories to authorize the upgrade. Validate that material terms are preserved, or use the propose-accept pattern.

```haskell
    choice ProposeUpgrade : ContractId UpgradeProposal
      controller issuer
      do
        create UpgradeProposal with
          issuer; holder; amount; oldContractCid = self

template UpgradeProposal with
    issuer : Party
    holder : Party
    amount : Decimal
    oldContractCid : ContractId TokenV1
  where
    signatory issuer
    observer holder

    choice AcceptUpgrade : ContractId TokenV2
      controller holder
      do
        exercise oldContractCid Archive
        create TokenV2 with issuer; holder; amount; fee = 0.0

```

### Denial-of-service via choice spam

-   **Severity:** Medium
-   **Description:** If a nonconsuming choice has a permissive controller (e.g., any observer), a malicious party can repeatedly exercise it, generating a high volume of transactions. While this does not corrupt state, it can degrade ledger performance, inflate storage costs, and overwhelm downstream automation (e.g., DAML triggers).
-   **Exploit Scenario:**

```haskell
template Bulletin with
    admin : Party
    readers : [Party]
  where
    signatory admin
    observer readers

    nonconsuming choice PostComment : ContractId Comment
      with
        author : Party
        body : Text
      controller author
      do
        assert (author `elem` readers)
        create Comment with bulletin = self; author; body

```

Any reader can flood the ledger with comments.

-   **Recommendation:** Implement application-level rate limiting. Consider using a consuming intermediary (e.g., a `CommentToken`) that limits the number of times a party can exercise the choice.

```haskell
template CommentToken with
    admin : Party
    commenter : Party
  where
    signatory admin
    observer commenter

    choice UseComment : ContractId Comment
      with
        bulletinCid : ContractId Bulletin
        body : Text
      controller commenter
      do
        create Comment with bulletin = bulletinCid; author = commenter; body
        -- Token is consumed; commenter must be issued a new one to comment again

```

### Privacy inference via transaction timing

-   **Severity:** Low
-   **Description:** Although Canton provides sub-transaction privacy (parties only see the parts of a transaction that involve them), a party can still infer information from **when** they receive transaction notifications. For example, if Party A and Party B are both observers on different sub-parts of a workflow, timing correlations can reveal that a related event occurred even if the content is hidden.
-   **Exploit Scenario:**

Party C executes a trade with Party A. Party B, who is an observer on a separate settlement contract, notices a new contract appear at a specific timestamp. By correlating the timing with known market events, Party B infers that Party A executed a trade.

-   **Recommendation:** Introduce random delay or batching at the application/trigger layer to decorrelate transaction timing. Minimize the number of observers on intermediate workflow contracts. Evaluate whether parties need to observe real-time updates or can receive periodic snapshots instead.

----------

## Case Analysis

### Incorrect controller allows unauthorized token transfer

##### Vulnerability Example

A token template allows the `receiver` field of a `Transfer` choice to also serve as the controller, meaning the intended recipient can forcibly take tokens from the owner.

```haskell
template Token with
    issuer : Party
    owner : Party
    amount : Decimal
  where
    signatory issuer, owner

    choice Transfer : ContractId Token
      with
        receiver : Party
      controller receiver  -- BUG: receiver can take tokens without owner's consent
      do
        create this with owner = receiver

```

##### Fix

The `owner` (not the receiver) should control the transfer. The receiver should only be able to accept a transfer proposal.

```haskell
template Token with
    issuer : Party
    owner : Party
    amount : Decimal
  where
    signatory issuer, owner

    choice ProposeTransfer : ContractId TransferProposal
      with
        receiver : Party
      controller owner
      do
        create TransferProposal with token = this; receiver

template TransferProposal with
    token : Token
    receiver : Party
  where
    signatory (signatory token)
    observer receiver

    choice AcceptTransfer : ContractId Token
      controller receiver
      do
        create token with owner = receiver

    choice CancelTransfer : ContractId Token
      controller token.owner
      do
        create token

```

-   **Relevance:** This pattern mirrors the Parity Wallet authorization flaw cited in the Canton whitepaper, where insufficient authorization checks allowed an attacker to take ownership of the multi-sig wallet contract. DAML's declarative authorization model makes the correct pattern easier to implement, but the developer must still choose the right controller.

### Privacy leakage through overly broad observer lists

##### Vulnerability Example

A supply-chain contract adds all downstream participants as observers on the manufacturer's pricing contract.

```haskell
template SupplyContract with
    manufacturer : Party
    distributor : Party
    retailers : [Party]
    wholesalePrice : Decimal
  where
    signatory manufacturer, distributor
    observer retailers  -- All retailers see the wholesale price

```

##### Fix

Create separate contracts with different visibility scopes. Retailers see only the retail price.

```haskell
template WholesaleContract with
    manufacturer : Party
    distributor : Party
    wholesalePrice : Decimal
  where
    signatory manufacturer, distributor
    -- No observer: retailers cannot see this

template RetailPriceList with
    distributor : Party
    retailers : [Party]
    retailPrice : Decimal
  where
    signatory distributor
    observer retailers
    -- Retailers see only the retail price, not the wholesale margin

```

-   **Relevance:** In regulated financial markets, leaking pricing information between counterparties can constitute a compliance violation. Canton's sub-transaction privacy is only effective if the contract-level observer lists are correctly designed.

### Contract key race condition in concurrent submissions

##### Vulnerability Example

A username registration system relies on `lookupByKey` to enforce uniqueness.

```haskell
template Username with
    registrar : Party
    user : Party
    name : Text
  where
    signatory registrar, user
    key (registrar, name) : (Party, Text)
    maintainer key._1

template RegistrationService with
    registrar : Party
  where
    signatory registrar

    nonconsuming choice Register : ContractId Username
      with
        user : Party
        name : Text
      controller user
      do
        optCid <- lookupByKey @Username (registrar, name)
        case optCid of
          Some _ -> abort "Username taken"
          None -> create Username with registrar; user; name

```

Two users submit `Register` with the same `name` concurrently. In Canton, both `lookupByKey` calls may return `None`, and both transactions may commit, resulting in two users with the same username.

##### Fix

Use a consuming generator to serialize registration.

```haskell
template RegistrationService with
    registrar : Party
  where
    signatory registrar

    -- Consuming choice ensures serialization
    choice Register : (ContractId RegistrationService, ContractId Username)
      with
        user : Party
        name : Text
      controller registrar
      do
        optCid <- lookupByKey @Username (registrar, name)
        case optCid of
          Some _ -> abort "Username taken"
          None -> do
            userCid <- create Username with registrar; user; name
            svcCid <- create this
            return (svcCid, userCid)

```

-   **Relevance:** The Canton documentation explicitly warns about this behavior. Any application requiring strong uniqueness guarantees must account for Canton's eventual consistency semantics for contract keys.

----------

## Recommended Tooling and Practices

1.  **Daml Script testing:** Write comprehensive `daml script` tests covering all choice paths, authorization failures, and edge cases. Aim for full branch coverage. Test concurrent scenarios using multi-party test scripts.
    
2.  **Static analysis with `daml lint`:** Run `daml lint` on all template code to catch common issues such as unused variables, redundant imports, and simple logic errors.
    
3.  **Property-based testing with `daml-props`:** Where available, use property-based testing to generate random inputs and verify invariants (e.g., "balance is always non-negative after any sequence of choices").
    
4.  **Formal verification with `daml-verify` / CPN modeling:** For high-value contracts, model the contract's state machine using colored Petri nets (CPNs) or other formal methods to verify properties like deadlock freedom, liveness, and authorization correctness.
    
5.  **Template upgrade discipline:** Use Daml's package versioning and upgrade mechanism. Always require multi-party consent for upgrades. Test upgrade paths in a sandbox environment before deploying to production.
    
6.  **Peer review and audit:** All DAML templates handling financial assets, governance, or sensitive data should undergo independent security review by auditors familiar with DAML's authorization and privacy model.
    
7.  **Canton domain configuration hardening:**
    
    -   Set tight `ledger-time-record-time-tolerance` values to minimize time manipulation.
    -   Configure command deduplication to prevent replay.
    -   Use TLS and KMS for all participant-to-domain communication.
    -   Rotate Canton long-term keys periodically.
8.  **Principle of minimal authority:** Each contract should grant the minimum necessary visibility (observers) and action rights (choices/controllers) required for its business purpose. Regularly audit observer lists and choice controllers.
    
9.  **Monitoring and automation:** Deploy DAML triggers with appropriate guards and rate limits. Monitor ledger transaction rates for anomalies. Set up alerts for unexpected contract archives or mass creation events.
    
10.  **Documentation and threat modeling:** Maintain a threat model for each DAML application that maps parties, their roles, and the trust assumptions. Identify which parties are trusted vs. potentially adversarial and design templates accordingly.
