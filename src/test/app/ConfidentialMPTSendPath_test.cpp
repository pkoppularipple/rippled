#include <test/jtx.h>
#include <test/jtx/credentials.h>
#include <test/jtx/delegate.h>
#include <test/jtx/deposit.h>
#include <test/jtx/mpt.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/jss.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace xrpl::test {

class ConfidentialMPTSendPath_test : public beast::unit_test::Suite
{
    template <typename T>
    static std::string
    hexOf(T const& arr)
    {
        return strHex(Slice{arr.data(), arr.size()});
    }

    static std::string
    rawStr(std::array<std::uint8_t, cmpt::kPointSize> const& a)
    {
        return std::string(reinterpret_cast<char const*>(a.data()), a.size());
    }

    // Build a ConfidentialMPTConvert JSON. When holderSk is supplied a new
    // holder key is registered (with a Schnorr proof); otherwise the key is
    // assumed already present on the MPToken.
    static json::Value
    convertJV(
        jtx::Env& env,
        jtx::Account const& account,
        MPTID const& id,
        std::uint64_t amount,
        cmpt::ECPoint const& holderPub,
        cmpt::ECPoint const& issuerPub,
        std::optional<cmpt::Scalar> const& holderSecret,
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt,
        std::optional<std::uint32_t> seqOverride = std::nullopt)
    {
        cmpt::Scalar const k = cmpt::Scalar::random();
        auto const holderCt = cmpt::ElGamalCiphertext::encrypt(holderPub, amount, k);
        auto const issuerCt = cmpt::ElGamalCiphertext::encrypt(issuerPub, amount, k);

        json::Value jv;
        jv[jss::TransactionType] = "ConfidentialMPTConvert";
        jv[jss::Account] = account.human();
        // Confidential transactions carry a 10x base fee (XLS-0096 §14). Set it
        // explicitly so the harness does not autofill the plain 1x base fee.
        jv[jss::Fee] = to_string(
            env.current()->fees().base *
            static_cast<XRPAmount::value_type>(cmpt::kConfidentialFeeMultiplier));
        jv[sfMPTokenIssuanceID] = to_string(id);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] = hexOf(holderCt.serialize());
        jv[sfIssuerEncryptedAmount] = hexOf(issuerCt.serialize());
        jv[sfBlindingFactor] = hexOf(k.bytes());
        // The auditor mirror shares the disclosed blinding factor so that
        // deterministic verification reconstructs it exactly.
        if (auditorPub)
            jv[sfAuditorEncryptedAmount] =
                hexOf(cmpt::ElGamalCiphertext::encrypt(*auditorPub, amount, k).serialize());
        if (holderSecret)
        {
            // Bind the registration proof to the transaction the account is
            // about to submit. For a sequence-based transaction env.seq(account)
            // is the sequence jtx autofills; for a ticketed transaction
            // seqOverride carries the ticket number (getSeqValue()).
            auto const seqValue = seqOverride.value_or(env.seq(account));
            auto const contextId = cmpt::convertContextId(account.id(), id, seqValue);
            jv[sfHolderEncryptionKey] = hexOf(holderPub.serialize());
            jv[sfZKProof] = hexOf(cmpt::SchnorrProof::prove(
                                      *holderSecret,
                                      holderPub,
                                      Slice{contextId.data(), contextId.size()})
                                      .serialize());
        }
        return jv;
    }

    static json::Value
    mergeJV(jtx::Account const& account, MPTID const& id)
    {
        json::Value jv;
        jv[jss::TransactionType] = "ConfidentialMPTMergeInbox";
        jv[jss::Account] = account.human();
        // Confidential transactions carry a 10x base fee (XLS-0096 §14). The
        // unit-test reference base fee is UNIT_TEST_REFERENCE_FEE; set the fee
        // explicitly so the harness does not autofill the plain 1x base fee.
        jv[jss::Fee] = std::to_string(
            std::uint64_t{UNIT_TEST_REFERENCE_FEE} * cmpt::kConfidentialFeeMultiplier);
        jv[sfMPTokenIssuanceID] = to_string(id);
        return jv;
    }

    void
    testConvert(FeatureBitset features)
    {
        testcase("ConfidentialMPTConvert");
        using namespace jtx;

        Account const alice("alice");  // issuer
        Account const bob("bob");      // holder

        auto const issuerSk = cmpt::ElGamalSecretKey::random();
        auto const issuerPub = issuerSk.publicKey();
        auto const bobSk = cmpt::ElGamalSecretKey::random();
        auto const bobPub = bobSk.publicKey();

        // Amendment-gated: the transaction type is unavailable without the
        // ConfidentialMPT amendment.
        {
            Env env{*this, features - featureConfidentialMPT};
            MPTTester mpt(env, alice, {.holders = {bob}});
            mpt.create({.flags = tfMPTCanTransfer});
            mpt.authorize({.account = bob});
            env(convertJV(env, bob, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
                Ter(temDISABLED));
        }

        // Capability-flag rejection: the issuance does not allow confidential
        // amounts.
        {
            Env env{*this, features};
            MPTTester mpt(env, alice, {.holders = {bob}});
            mpt.create({.flags = tfMPTCanTransfer});
            mpt.authorize({.account = bob});
            mpt.pay(alice, bob, 1000);
            env(convertJV(env, bob, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
                Ter(tecNO_PERMISSION));
        }

        // Issuer cannot convert its own issuance.
        {
            Env env{*this, features};
            MPTTester mpt(env, alice, {.holders = {bob}});
            mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
            mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
            env(convertJV(env, alice, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
                Ter(temMALFORMED));
        }
    }

public:
    void
    run() override
    {
        FeatureBitset const all{jtx::testableAmendments()};
        testConvert(all);
        testConvertSuccess(all);
        testMergeInbox(all);
        testSend(all);
        testNonDelegable(all);
        testDepositAuth(all);
        testFeeMultiplier(all);
        testMergeInboxLock(all);
    }

private:
    void
    testConvertSuccess(FeatureBitset features);
    void
    testMergeInbox(FeatureBitset features);
    void
    testSend(FeatureBitset features);
    void
    testNonDelegable(FeatureBitset features);
    void
    testDepositAuth(FeatureBitset features);
    void
    testFeeMultiplier(FeatureBitset features);
    void
    testMergeInboxLock(FeatureBitset features);

    static json::Value
    sendJV(
        jtx::Env& env,
        jtx::Account const& from,
        jtx::Account const& to,
        MPTID const& id,
        std::uint64_t amount,
        std::uint64_t remaining,
        cmpt::Scalar const& senderSecret,
        cmpt::ECPoint const& senderPub,
        cmpt::ECPoint const& destPub,
        cmpt::ECPoint const& issuerPub,
        cmpt::ElGamalCiphertext const& senderSpending,
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt,
        std::optional<std::uint32_t> seqOverride = std::nullopt,
        std::uint8_t rangeBits = 63);

    static cmpt::ElGamalCiphertext
    readSpending(jtx::Env& env, MPTID const& id, jtx::Account const& a);

    // Read a holder's issuer-mirror confidential balance ciphertext (or the
    // encryption of zero when the field is absent).
    static cmpt::ElGamalCiphertext
    readIssuerMirror(jtx::Env& env, MPTID const& id, jtx::Account const& a);

    // Build a ConfidentialMPTConvertBack JSON (compact balance proof + 63-bit
    // range proof), mirroring the dedicated ConvertBack suite's builder.
    static json::Value
    convertBackJV(
        jtx::Env& env,
        jtx::Account const& account,
        MPTID const& id,
        std::uint64_t amount,
        std::uint64_t remaining,
        cmpt::Scalar const& holderSecret,
        cmpt::ECPoint const& holderPub,
        cmpt::ECPoint const& issuerPub,
        cmpt::ElGamalCiphertext const& spending);

    // Build a ConfidentialMPTClawback JSON (compact clawback proof), mirroring
    // the dedicated Clawback suite's builder.
    static json::Value
    clawbackJV(
        jtx::Env& env,
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& id,
        std::uint64_t amount,
        cmpt::Scalar const& issuerSecret,
        cmpt::ElGamalCiphertext const& issuerMirror);
};

cmpt::ElGamalCiphertext
ConfidentialMPTSendPath_test::readIssuerMirror(
    jtx::Env& env,
    MPTID const& id,
    jtx::Account const& a)
{
    auto const sle = env.le(keylet::mptoken(id, a.id()));
    if (sle && sle->isFieldPresent(sfIssuerEncryptedBalance))
    {
        auto const b = sle->getFieldVL(sfIssuerEncryptedBalance);
        if (auto ct = cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()}))
            return *ct;
    }
    return cmpt::ElGamalCiphertext::encryptZero();
}

json::Value
ConfidentialMPTSendPath_test::convertBackJV(
    jtx::Env& env,
    jtx::Account const& account,
    MPTID const& id,
    std::uint64_t amount,
    std::uint64_t remaining,
    cmpt::Scalar const& holderSecret,
    cmpt::ECPoint const& holderPub,
    cmpt::ECPoint const& issuerPub,
    cmpt::ElGamalCiphertext const& spending)
{
    using namespace cmpt;
    Scalar const k = Scalar::random();
    auto const holderCt = ElGamalCiphertext::encrypt(holderPub, amount, k);
    auto const issuerCt = ElGamalCiphertext::encrypt(issuerPub, amount, k);

    auto const postDebit = spending - holderCt;
    Scalar const rb = Scalar::random();
    auto const [rangeBalance, balanceCommit] = RangeProof::prove(remaining, rb, 63);
    std::uint32_t version = 0;
    if (auto const sle = env.le(keylet::mptoken(id, account.id()));
        sle && sle->isFieldPresent(sfConfidentialBalanceVersion))
        version = sle->getFieldU32(sfConfidentialBalanceVersion);
    auto const contextId =
        convertBackContextId(account.id(), id, env.seq(account), version);
    auto const compactBalance = CompactConvertBackProof::prove(
        holderSecret,
        remaining,
        rb,
        holderPub,
        postDebit,
        balanceCommit,
        Slice{contextId.data(), contextId.size()});

    Blob bundle;
    auto append = [&](auto const& a) {
        bundle.insert(bundle.end(), a.begin(), a.end());
    };
    append(compactBalance.serialize());
    auto const rangeBytes = rangeBalance.serialize();
    bundle.insert(bundle.end(), rangeBytes.begin() + 1, rangeBytes.end());

    json::Value jv;
    jv[jss::TransactionType] = "ConfidentialMPTConvertBack";
    jv[jss::Account] = account.human();
    jv[sfMPTokenIssuanceID] = to_string(id);
    jv[sfMPTAmount] = std::to_string(amount);
    jv[sfHolderEncryptedAmount] = hexOf(holderCt.serialize());
    jv[sfIssuerEncryptedAmount] = hexOf(issuerCt.serialize());
    jv[sfBlindingFactor] = hexOf(k.bytes());
    jv[sfBalanceCommitment] = hexOf(balanceCommit.serialize());
    jv[sfZKProof] = strHex(bundle);
    return jv;
}

json::Value
ConfidentialMPTSendPath_test::clawbackJV(
    jtx::Env& env,
    jtx::Account const& issuer,
    jtx::Account const& holder,
    MPTID const& id,
    std::uint64_t amount,
    cmpt::Scalar const& issuerSecret,
    cmpt::ElGamalCiphertext const& issuerMirror)
{
    using namespace cmpt;
    auto const issuerPub = ECPoint::mulBase(issuerSecret);
    auto const contextId =
        clawbackContextId(issuer.id(), id, env.seq(issuer), holder.id());
    auto const proof = CompactClawbackProof::prove(
        issuerSecret,
        amount,
        issuerPub,
        issuerMirror,
        Slice{contextId.data(), contextId.size()});

    json::Value jv;
    jv[jss::TransactionType] = "ConfidentialMPTClawback";
    jv[jss::Account] = issuer.human();
    jv[sfHolder] = holder.human();
    jv[sfMPTokenIssuanceID] = to_string(id);
    jv[sfMPTAmount] = std::to_string(amount);
    jv[sfZKProof] = hexOf(proof.serialize());
    return jv;
}

cmpt::ElGamalCiphertext
ConfidentialMPTSendPath_test::readSpending(
    jtx::Env& env,
    MPTID const& id,
    jtx::Account const& a)
{
    auto const sle = env.le(keylet::mptoken(id, a.id()));
    auto const b = sle->getFieldVL(sfConfidentialBalanceSpending);
    return *cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()});
}

json::Value
ConfidentialMPTSendPath_test::sendJV(
    jtx::Env& env,
    jtx::Account const& from,
    jtx::Account const& to,
    MPTID const& id,
    std::uint64_t amount,
    std::uint64_t remaining,
    cmpt::Scalar const& senderSecret,
    cmpt::ECPoint const& senderPub,
    cmpt::ECPoint const& destPub,
    cmpt::ECPoint const& issuerPub,
    cmpt::ElGamalCiphertext const& senderSpending,
    std::optional<cmpt::ECPoint> const& auditorPub,
    std::optional<std::uint32_t> seqOverride,
    std::uint8_t rangeBits)
{
    using namespace cmpt;

    // Bind every proof to the transaction the sender is about to submit. The
    // version is the sender's current confidential balance version; for a
    // ticketed transaction seqOverride carries the ticket number
    // (getSeqValue()), otherwise env.seq(from) is the autofilled sequence.
    auto const sleSender = env.le(keylet::mptoken(id, from.id()));
    std::uint32_t const version =
        (sleSender && sleSender->isFieldPresent(sfConfidentialBalanceVersion))
        ? sleSender->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    auto const seqValue = seqOverride.value_or(env.seq(from));
    auto const contextId =
        cmpt::sendContextId(from.id(), id, seqValue, to.id(), version);
    Slice const ctxId{contextId.data(), contextId.size()};

    // Shared-randomness model: every recipient mirror reuses one ciphertext
    // nonce r, so all share C1 = r*G. The amount commitment's blinding factor
    // is that same r (PC_m = m*G + r*H), as the compact proof requires.
    Scalar const r = Scalar::random();
    auto const senderCt = ElGamalCiphertext::encrypt(senderPub, amount, r);
    auto const destCt = ElGamalCiphertext::encrypt(destPub, amount, r);
    auto const issuerCt = ElGamalCiphertext::encrypt(issuerPub, amount, r);

    auto const postDebit = senderSpending - senderCt;
    Scalar const rho = Scalar::random();

    // Single aggregated Bulletproof over both values: the transfer amount
    // (blinded by the shared nonce r, so its commitment is PC_m) and the
    // remaining spending balance (blinded by rho). Commitment order is
    // {amount, balance}, matching the verifier.
    auto const [range, rangeCommits] = RangeProof::proveAggregated(
        {amount, remaining}, {r, rho}, rangeBits, ctxId);
    auto const& amountCommit = rangeCommits[0];
    auto const& balanceCommit = rangeCommits[1];

    // Recipient mirrors in the canonical order [sender, dest, issuer, ...].
    std::vector<ElGamalPublicKey> recipientKeys{senderPub, destPub, issuerPub};
    std::vector<ElGamalCiphertext> recipientCts{senderCt, destCt, issuerCt};

    // Optional auditor mirror: a fresh ciphertext under the same shared r.
    std::optional<ElGamalCiphertext> auditorCt;
    if (auditorPub)
    {
        auditorCt = ElGamalCiphertext::encrypt(*auditorPub, amount, r);
        recipientKeys.push_back(*auditorPub);
        recipientCts.push_back(*auditorCt);
    }

    auto const standard = CompactStandardProof::prove(
        senderSecret,
        amount,
        remaining,
        r,
        rho,
        recipientKeys,
        recipientCts,
        amountCommit,
        senderPub,
        postDebit,
        balanceCommit,
        ctxId);

    Blob bundle;
    auto append = [&](auto const& a) {
        bundle.insert(bundle.end(), a.begin(), a.end());
    };
    append(standard.serialize());
    append(range.serializeAggregated());

    json::Value jv;
    jv[jss::TransactionType] = "ConfidentialMPTSend";
    jv[jss::Account] = from.human();
    // Confidential transactions carry a 10x base fee (XLS-0096 §14). Set it
    // explicitly so the harness does not autofill the plain 1x base fee.
    jv[jss::Fee] = to_string(
        env.current()->fees().base *
        static_cast<XRPAmount::value_type>(cmpt::kConfidentialFeeMultiplier));
    jv[jss::Destination] = to.human();
    jv[sfMPTokenIssuanceID] = to_string(id);
    jv[sfSenderEncryptedAmount] = hexOf(senderCt.serialize());
    jv[sfDestinationEncryptedAmount] = hexOf(destCt.serialize());
    jv[sfIssuerEncryptedAmount] = hexOf(issuerCt.serialize());
    if (auditorCt)
        jv[sfAuditorEncryptedAmount] = hexOf(auditorCt->serialize());
    jv[sfAmountCommitment] = hexOf(amountCommit.serialize());
    jv[sfBalanceCommitment] = hexOf(balanceCommit.serialize());
    jv[sfZKProof] = strHex(bundle);
    return jv;
}

void
ConfidentialMPTSendPath_test::testConvertSuccess(FeatureBitset features)
{
    testcase("ConfidentialMPTConvert success and accounting");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    // Success: COA increments, public balance debited, state initialized.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto const id = mpt.issuanceID();
        env(convertJV(env, bob, id, 400, bobPub, issuerPub, bobSk.x));
        env.close();

        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU64(sfMPTAmount) == 600);
        BEAST_EXPECT(tok && tok->isFieldPresent(sfConfidentialBalanceInbox));
        BEAST_EXPECT(tok && tok->isFieldPresent(sfConfidentialBalanceSpending));
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == 0);

        auto const iss = env.le(keylet::mptIssuance(id));
        BEAST_EXPECT(
            iss && iss->isFieldPresent(sfConfidentialOutstandingAmount) &&
            iss->getFieldU64(sfConfidentialOutstandingAmount) == 400);
        // The public OutstandingAmount is unchanged by the conversion.
        BEAST_EXPECT(iss && iss->getFieldU64(sfOutstandingAmount) == 1000);
    }

    // A tampered amount (ciphertext does not match the claimed public amount)
    // is rejected by deterministic verification.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);

        auto jv = convertJV(env, bob, mpt.issuanceID(), 400, bobPub, issuerPub, bobSk.x);
        jv[sfMPTAmount] = std::to_string(401);  // mismatch
        env(jv, Ter(tecBAD_PROOF));
    }

    // Converting more than the public balance fails.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(convertJV(env, bob, mpt.issuanceID(), 2000, bobPub, issuerPub, bobSk.x),
            Ter(tecINSUFFICIENT_FUNDS));
    }

    // Audited issuance: a valid auditor ciphertext is accepted and mirrored.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set(
            {.account = alice,
             .issuerEncryptionKey = rawStr(issuerPub.serialize()),
             .auditorEncryptionKey = rawStr(auditorPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();
        env(convertJV(env, bob, id, 400, bobPub, issuerPub, bobSk.x, auditorPub));
        env.close();
        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->isFieldPresent(sfAuditorEncryptedBalance));
    }

    // Non-audited issuance must reject an attached auditor ciphertext: an
    // issuance with no auditor key may not accept an unverified auditor mirror.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(convertJV(
                env, bob, mpt.issuanceID(), 400, bobPub, issuerPub, bobSk.x, auditorPub),
            Ter(tecNO_PERMISSION));
    }

    // Ticketed conversion exercises the SeqProxy binding at key registration. A
    // ticketed transaction carries sfSequence == 0, so a proof bound to
    // sequence 0 (the raw sfSequence) is rejected: the verifier binds the
    // registration context to getSeqValue(), the ticket number. A proof bound
    // to the ticket number is accepted.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();

        std::uint32_t const ticketSeq = env.seq(bob) + 1;
        env(ticket::create(bob, 2));
        env.close();

        // Bound to sequence 0 (the literal sfSequence of a ticketed tx) is
        // rejected.
        env(convertJV(
                env, bob, id, 400, bobPub, issuerPub, bobSk.x, std::nullopt, 0u),
            ticket::Use(ticketSeq),
            Ter(tecBAD_PROOF));

        // Bound to the ticket number (getSeqValue()) is accepted.
        env(convertJV(
                env, bob, id, 400, bobPub, issuerPub, bobSk.x, std::nullopt,
                ticketSeq + 1),
            ticket::Use(ticketSeq + 1));
        env.close();

        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU64(sfMPTAmount) == 600);
        BEAST_EXPECT(tok && tok->isFieldPresent(sfHolderEncryptionKey));
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == 0);
    }
}

void
ConfidentialMPTSendPath_test::testMergeInbox(FeatureBitset features)
{
    testcase("ConfidentialMPTMergeInbox");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();

        env(convertJV(env, bob, id, 400, bobPub, issuerPub, bobSk.x));
        env.close();

        // Issuer cannot merge.
        env(mergeJV(alice, id), Ter(temMALFORMED));

        env(mergeJV(bob, id));
        env.close();

        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == 1);

        // The merged spending balance decrypts to the converted amount.
        auto const spending = readSpending(env, id, bob);
        BEAST_EXPECT(spending.decrypt(bobSk.x, 2000) == 400);
    }
}

void
ConfidentialMPTSendPath_test::testSend(FeatureBitset features)
{
    testcase("ConfidentialMPTSend");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    Account const carol("carol");
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();
    auto const carolSk = cmpt::ElGamalSecretKey::random();
    auto const carolPub = carolSk.publicKey();

    auto setup = [&](Env& env) -> MPTID {
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();
        // bob funds his confidential spending balance.
        env(convertJV(env, bob, id, 1000, bobPub, issuerPub, bobSk.x));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        // carol opts in with a zero-amount conversion.
        env(convertJV(env, carol, id, 0, carolPub, issuerPub, carolSk.x));
        env.close();
        env(mergeJV(carol, id));
        env.close();
        return id;
    };

    // Success: value moves from bob's spending balance to carol's inbox.
    {
        Env env{*this, features};
        auto const id = setup(env);

        auto const before = env.le(keylet::mptoken(id, bob.id()))
                                ->getFieldU32(sfConfidentialBalanceVersion);
        env(sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob)));
        env.close();

        // Sender's spending balance now decrypts to the remainder and the
        // version was bumped.
        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == before + 1);
        BEAST_EXPECT(readSpending(env, id, bob).decrypt(bobSk.x, 2000) == 600);

        // Public balances and outstanding amounts are unchanged.
        auto const iss = env.le(keylet::mptIssuance(id));
        BEAST_EXPECT(iss && iss->getFieldU64(sfOutstandingAmount) == 1000);
        BEAST_EXPECT(
            iss && iss->getFieldU64(sfConfidentialOutstandingAmount) == 1000);

        // carol merges her inbox and recovers the transferred amount.
        env(mergeJV(carol, id));
        env.close();
        BEAST_EXPECT(readSpending(env, id, carol).decrypt(carolSk.x, 2000) == 400);
    }

    // A tampered proof bundle is rejected.
    {
        Env env{*this, features};
        auto const id = setup(env);
        auto jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        auto proof = *strUnHex(jv[sfZKProof].asString());
        proof[0] ^= 0x01;
        jv[sfZKProof] = strHex(proof);
        env(jv, Ter(tecBAD_PROOF));
    }

    // A ZKProof bundle that is not exactly 946 bytes is rejected up front in
    // preflight with temMALFORMED, before any proof verification. This guards
    // against the legacy two-range-proof layout (~1570 bytes) or any other
    // mis-sized bundle, and is distinct from the tecBAD_PROOF a same-size but
    // tampered bundle produces.
    {
        Env env{*this, features};
        auto const id = setup(env);
        auto const jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        auto const proof = *strUnHex(jv[sfZKProof].asString());

        // Truncated bundle (one byte short).
        {
            auto shortJv = jv;
            auto shortProof = proof;
            shortProof.pop_back();
            shortJv[sfZKProof] = strHex(shortProof);
            env(shortJv, Ter(temMALFORMED));
        }

        // Oversized bundle (one trailing byte, mimicking a wider layout).
        {
            auto longJv = jv;
            auto longProof = proof;
            longProof.push_back(0x00);
            longJv[sfZKProof] = strHex(longProof);
            env(longJv, Ter(temMALFORMED));
        }
    }

    // The aggregated range proof must be exactly 63-bit. A structurally valid
    // 946-byte bundle whose range proof asserts a wider [0, 2^64) bound is
    // rejected, so the preclaim's [0, 2^63) guarantee on the amount and
    // post-debit balance cannot be weakened by swapping in a wider proof.
    {
        Env env{*this, features};
        auto const id = setup(env);
        env(sendJV(
                env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub,
                issuerPub, readSpending(env, id, bob), std::nullopt,
                std::nullopt, 64),
            Ter(tecBAD_PROOF));
    }

    // The bundle is bound to the transaction context_id (sender, issuance,
    // sequence, destination, balance version). A bundle generated for a
    // different sequence no longer verifies; one built for the actual sequence
    // is accepted.
    {
        Env env{*this, features};
        auto const id = setup(env);

        // Bound to the wrong sequence: rejected.
        env(sendJV(
                env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub,
                issuerPub, readSpending(env, id, bob), std::nullopt,
                env.seq(bob) + 99),
            Ter(tecBAD_PROOF));
        env.close();

        // Bound to the actual sequence: accepted.
        env(sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob)));
        env.close();
        BEAST_EXPECT(readSpending(env, id, bob).decrypt(bobSk.x, 2000) == 600);
    }

    // Ticketed send exercises the SeqProxy binding. A ticketed transaction
    // carries sfSequence == 0, so a proof bound to sequence 0 (the raw
    // sfSequence) is rejected: the verifier binds the context to
    // getSeqValue(), which returns the ticket number. A proof bound to the
    // ticket number is accepted.
    {
        Env env{*this, features};
        auto const id = setup(env);

        std::uint32_t const ticketSeq = env.seq(bob) + 1;
        env(ticket::create(bob, 2));
        env.close();

        // Bound to sequence 0 (the literal sfSequence of a ticketed tx) is
        // rejected.
        env(sendJV(
                env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub,
                issuerPub, readSpending(env, id, bob), std::nullopt, 0u),
            ticket::Use(ticketSeq),
            Ter(tecBAD_PROOF));

        // Bound to the ticket number (getSeqValue()) is accepted.
        env(sendJV(
                env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub,
                issuerPub, readSpending(env, id, bob), std::nullopt,
                ticketSeq + 1),
            ticket::Use(ticketSeq + 1));
        env.close();
        BEAST_EXPECT(readSpending(env, id, bob).decrypt(bobSk.x, 2000) == 600);
    }

    // Audited issuance: the auditor mirror moves with a valid auditor
    // ciphertext and proof.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set(
            {.account = alice,
             .issuerEncryptionKey = rawStr(issuerPub.serialize()),
             .auditorEncryptionKey = rawStr(auditorPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();
        env(convertJV(env, bob, id, 1000, bobPub, issuerPub, bobSk.x, auditorPub));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        env(convertJV(env, carol, id, 0, carolPub, issuerPub, carolSk.x, auditorPub));
        env.close();
        env(mergeJV(carol, id));
        env.close();

        env(sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob), auditorPub));
        env.close();
        auto const tok = env.le(keylet::mptoken(id, carol.id()));
        BEAST_EXPECT(tok && tok->isFieldPresent(sfAuditorEncryptedBalance));
    }

    // Non-audited issuance must reject an attached auditor ciphertext: an
    // issuance with no auditor key may not accept an unverified auditor mirror.
    {
        Env env{*this, features};
        auto const id = setup(env);
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        auto jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jv[sfAuditorEncryptedAmount] =
            hexOf(cmpt::ElGamalCiphertext::encrypt(auditorPub, 400).serialize());
        env(jv, Ter(tecNO_PERMISSION));
    }

    // Amendment-gated.
    {
        Env env{*this, features - featureConfidentialMPT};
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        env(sendJV(
                env, bob, carol, mpt.issuanceID(), 1, 0, bobSk.x, bobPub, carolPub,
                issuerPub, cmpt::ElGamalCiphertext::encryptZero()),
            Ter(temDISABLED));
    }

    // CredentialIDs requires featureCredentials.
    {
        Env env{*this, features - featureCredentials};
        auto const id = setup(env);
        auto jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jv[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jv[sfCredentialIDs.jsonName].append("ABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCDABCD");
        env(jv, Ter(temDISABLED));
    }
}

void
ConfidentialMPTSendPath_test::testNonDelegable(FeatureBitset features)
{
    // XLS-0096: every confidential MPT transaction type is Delegation::
    // NotDelegable and defines no granular permission, so a transaction that
    // carries sfDelegate is rejected with temINVALID in Transactor::preflight1
    // before any field, proof, or ledger-state check runs. This pins that
    // guarantee: a delegate must never be able to act on a holder's
    // confidential balance (e.g. by registering its own encryption key).
    testcase("ConfidentialMPT transactions are non-delegable");
    using namespace jtx;

    // featureConfidentialMPT and the delegation amendment must both be active
    // for the delegation gate to be exercised (rather than temDISABLED).
    BEAST_EXPECT(features[featureConfidentialMPT]);
    BEAST_EXPECT(features[featurePermissionDelegationV1_1]);

    Account const alice("alice");  // issuer
    Account const bob("bob");      // holder / sender
    Account const carol("carol");  // destination / clawback target
    Account const dave("dave");    // delegate (never granted any permission)

    auto const issuerSk = cmpt::ElGamalSecretKey::random();
    auto const issuerPub = issuerSk.publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();
    auto const carolSk = cmpt::ElGamalSecretKey::random();
    auto const carolPub = carolSk.publicKey();

    Env env{*this, features};
    env.fund(XRP(10000), dave);
    env.close();

    MPTTester mpt(env, alice, {.holders = {bob, carol}});
    mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
    mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
    mpt.authorize({.account = bob});
    mpt.authorize({.account = carol});
    mpt.pay(alice, bob, 1000);
    auto const id = mpt.issuanceID();

    // Fund bob's confidential spending balance so Send/ConvertBack/Clawback
    // operate against real state (though preflight rejects before that matters).
    env(convertJV(env, bob, id, 1000, bobPub, issuerPub, bobSk.x));
    env.close();
    env(mergeJV(bob, id));
    env.close();
    env(convertJV(env, carol, id, 0, carolPub, issuerPub, carolSk.x));
    env.close();
    env(mergeJV(carol, id));
    env.close();

    // Each of the five confidential transaction types, submitted with
    // delegate::As(dave), must be rejected with temINVALID at preflight.

    // ConfidentialMPTConvert (tt 85).
    env(convertJV(env, bob, id, 100, bobPub, issuerPub, std::nullopt),
        delegate::As(dave),
        Ter(temINVALID));

    // ConfidentialMPTMergeInbox (tt 86).
    env(mergeJV(bob, id), delegate::As(dave), Ter(temINVALID));

    // ConfidentialMPTConvertBack (tt 87).
    env(convertBackJV(
            env, bob, id, 100, 900, bobSk.x, bobPub, issuerPub,
            readSpending(env, id, bob)),
        delegate::As(dave),
        Ter(temINVALID));

    // ConfidentialMPTSend (tt 88).
    env(sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob)),
        delegate::As(dave),
        Ter(temINVALID));

    // ConfidentialMPTClawback (tt 89) — issuer-initiated, still non-delegable.
    env(clawbackJV(
            env, alice, bob, id, 400, issuerSk.x,
            readIssuerMirror(env, id, bob)),
        delegate::As(dave),
        Ter(temINVALID));
}

void
ConfidentialMPTSendPath_test::testDepositAuth(FeatureBitset features)
{
    testcase("DepositAuth and Credentials enforcement");
    using namespace jtx;

    Account const alice("alice");   // MPT issuer
    Account const bob("bob");       // sender
    Account const carol("carol");   // receiver
    Account const credIssuer("credIssuer");  // Credential issuer (separate from MPT issuer)

    auto const issuerSk = cmpt::ElGamalSecretKey::random();
    auto const issuerPub = issuerSk.publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();
    auto const carolSk = cmpt::ElGamalSecretKey::random();
    auto const carolPub = carolSk.publicKey();

    std::string const credType = "abcdefgh";

    auto setup = [&](Env& env) -> MPTID {
        // Fund the credential issuer account
        env.fund(XRP(1000), credIssuer);
        env.close();

        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();
        // Bob funds his confidential spending balance
        env(convertJV(env, bob, id, 1000, bobPub, issuerPub, bobSk.x));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        // Carol opts in with zero-amount conversion
        env(convertJV(env, carol, id, 0, carolPub, issuerPub, carolSk.x));
        env.close();
        env(mergeJV(carol, id));
        env.close();
        return id;
    };

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(fset(carol, asfDepositAuth));
        env.close();
        auto jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        env(jv, Ter(tecNO_PERMISSION));
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(fset(carol, asfDepositAuth));
        env.close();
        env(deposit::auth(carol, bob));
        env.close();
        auto jv = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        env(jv);
        env.close();
        // Merge inbox to update balance
        env(mergeJV(carol, id));
        env.close();
        BEAST_EXPECT(readSpending(env, id, carol).decrypt(carolSk.x, 2000) == 400);
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(credentials::create(bob, credIssuer, credType));
        env.close();
        env(credentials::accept(bob, credIssuer, credType));
        env.close();
        auto const jv = credentials::ledgerEntry(env, bob, credIssuer, credType);
        std::string const credIdx = jv[jss::result][jss::index].asString();
        env(fset(carol, asfDepositAuth));
        env.close();
        auto jsend = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jsend[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jsend[sfCredentialIDs.jsonName].append(credIdx);
        env(jsend, Ter(tecNO_PERMISSION));
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(credentials::create(bob, credIssuer, credType));
        env.close();
        env(credentials::accept(bob, credIssuer, credType));
        env.close();
        auto const jv = credentials::ledgerEntry(env, bob, credIssuer, credType);
        std::string const credIdx = jv[jss::result][jss::index].asString();
        env(fset(carol, asfDepositAuth));
        env.close();
        env(deposit::authCredentials(carol, {{.issuer = credIssuer, .credType = credType}}));
        env.close();
        auto jsend = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jsend[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jsend[sfCredentialIDs.jsonName].append(credIdx);
        env(jsend);
        env.close();
        // Merge inbox to update balance
        env(mergeJV(carol, id));
        env.close();
        BEAST_EXPECT(readSpending(env, id, carol).decrypt(carolSk.x, 2000) == 400);
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(fset(carol, asfDepositAuth));
        env.close();
        env(deposit::authCredentials(carol, {{.issuer = credIssuer, .credType = credType}}));
        env.close();
        auto jsend = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jsend[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jsend[sfCredentialIDs.jsonName].append(
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
        env(jsend, Ter(tecBAD_CREDENTIALS));
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        auto jsend = sendJV(
            env, bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        env(jsend);
        env.close();
        // Merge inbox to update balance
        env(mergeJV(carol, id));
        env.close();
        BEAST_EXPECT(readSpending(env, id, carol).decrypt(carolSk.x, 2000) == 400);
    }
}

void
ConfidentialMPTSendPath_test::testFeeMultiplier(FeatureBitset features)
{
    testcase("Confidential MPT 10x base-fee multiplier (XLS-0096 §14)");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    Env env{*this, features};
    MPTTester mpt(env, alice, {.holders = {bob}});
    mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
    mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
    mpt.authorize({.account = bob});
    mpt.pay(alice, bob, 1000);
    auto const id = mpt.issuanceID();

    auto const baseDrops = env.current()->fees().base.drops();
    auto const requiredDrops =
        baseDrops * static_cast<XRPAmount::value_type>(cmpt::kConfidentialFeeMultiplier);

    // A confidential Convert paying only the ordinary 1x base fee is rejected:
    // the transactor requires cmpt::kConfidentialFeeMultiplier * base.
    env(convertJV(env, bob, id, 100, bobPub, issuerPub, bobSk.x),
        Fee(drops(XRPAmount{baseDrops})),
        Ter(telINSUF_FEE_P));

    // One drop short of the 10x requirement is still rejected.
    env(convertJV(env, bob, id, 100, bobPub, issuerPub, bobSk.x),
        Fee(drops(XRPAmount{requiredDrops - 1})),
        Ter(telINSUF_FEE_P));

    // Paying exactly the 10x base fee succeeds.
    env(convertJV(env, bob, id, 100, bobPub, issuerPub, bobSk.x),
        Fee(drops(XRPAmount{requiredDrops})));
    env.close();

    // The multiplier is scoped to confidential transactions only: an ordinary
    // public MPT payment on the same issuance still clears at the 1x base fee.
    mpt.pay(bob, alice, 100);

    // Multisignature surcharge is added at 1x, not scaled by the confidential
    // multiplier. With N signers the required fee is
    //   (multiplier * base) + (N * base),
    // not multiplier * (base + N * base). Give bob a two-signer list and submit
    // a multisigned confidential Convert with both signatures.
    Account const signer1("signer1");
    Account const signer2("signer2");
    env.fund(XRP(10000), signer1, signer2);
    env.close();
    env(signers(bob, 2, {{signer1, 1}, {signer2, 1}}));
    env.close();

    auto const mult =
        static_cast<XRPAmount::value_type>(cmpt::kConfidentialFeeMultiplier);
    // Correct required fee for two signers: 10*base + 2*base = 12*base.
    auto const msigRequired = (mult * baseDrops) + (2 * baseDrops);

    // One drop short of the multisig requirement is rejected.
    env(convertJV(env, bob, id, 50, bobPub, issuerPub, std::nullopt),
        Msig(signer1, signer2),
        Fee(drops(XRPAmount{msigRequired - 1})),
        Ter(telINSUF_FEE_P));

    // Exactly 12*base succeeds — the surcharge is not scaled by the multiplier
    // (which would have demanded 10*(base + 2*base) = 30*base).
    env(convertJV(env, bob, id, 50, bobPub, issuerPub, std::nullopt),
        Msig(signer1, signer2),
        Fee(drops(XRPAmount{msigRequired})));
    env.close();
}

void
ConfidentialMPTSendPath_test::testMergeInboxLock(FeatureBitset features)
{
    testcase("Confidential MPT MergeInbox lock enforcement (XLS-0096 §9.2.1.2)");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    // XLS-0096 §9.2.1.2 items 5 & 6: an individual-level or issuance-level lock
    // rejects the merge with tecLOCKED. Unlocking restores the ability to merge.
    Env env{*this, features};
    MPTTester mpt(env, alice, {.holders = {bob}});
    mpt.create(
        {.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount | tfMPTCanLock});
    mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
    mpt.authorize({.account = bob});
    mpt.pay(alice, bob, 1000);
    auto const id = mpt.issuanceID();

    env(convertJV(env, bob, id, 400, bobPub, issuerPub, bobSk.x));
    env.close();

    // Item 5: an individual lock on the holder's MPToken blocks the merge.
    mpt.set({.holder = bob, .flags = tfMPTLock});
    env(mergeJV(bob, id), Ter(tecLOCKED));

    mpt.set({.holder = bob, .flags = tfMPTUnlock});

    // Item 6: an issuance-level lock also blocks the merge.
    mpt.set({.account = alice, .flags = tfMPTLock});
    env(mergeJV(bob, id), Ter(tecLOCKED));

    mpt.set({.account = alice, .flags = tfMPTUnlock});
    env(mergeJV(bob, id));
    env.close();
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSendPath, app, xrpl);

}  // namespace xrpl::test
