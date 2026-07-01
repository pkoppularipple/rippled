#include <test/jtx.h>
#include <test/jtx/credentials.h>
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
        testDepositAuth(all);
    }

private:
    void
    testConvertSuccess(FeatureBitset features);
    void
    testMergeInbox(FeatureBitset features);
    void
    testSend(FeatureBitset features);
    void
    testDepositAuth(FeatureBitset features);

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
};

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

    auto const [rangeAmount, amountCommit] =
        RangeProof::prove(amount, r, rangeBits, ctxId);

    auto const postDebit = senderSpending - senderCt;
    Scalar const rho = Scalar::random();
    auto const [rangeBalance, balanceCommit] =
        RangeProof::prove(remaining, rho, rangeBits, ctxId);

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
    append(rangeAmount.serialize());
    append(rangeBalance.serialize());

    json::Value jv;
    jv[jss::TransactionType] = "ConfidentialMPTSend";
    jv[jss::Account] = from.human();
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

    // Range proofs must be exactly 63-bit. A structurally valid bundle whose
    // range proofs assert a wider [0, 2^64) bound is rejected, so the preclaim's
    // [0, 2^63) guarantee on the amount and post-debit balance cannot be
    // weakened by swapping in wider proofs.
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

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSendPath, app, xrpl);

}  // namespace xrpl::test
