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
#include <string>

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
        jtx::Account const& account,
        MPTID const& id,
        std::uint64_t amount,
        cmpt::ECPoint const& holderPub,
        cmpt::ECPoint const& issuerPub,
        std::optional<cmpt::Scalar> const& holderSecret,
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt)
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
            jv[sfHolderEncryptionKey] = hexOf(holderPub.serialize());
            jv[sfZKProof] =
                hexOf(cmpt::SchnorrProof::prove(*holderSecret, holderPub).serialize());
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
            env(convertJV(bob, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
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
            env(convertJV(bob, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
                Ter(tecNO_PERMISSION));
        }

        // Issuer cannot convert its own issuance.
        {
            Env env{*this, features};
            MPTTester mpt(env, alice, {.holders = {bob}});
            mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
            mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
            env(convertJV(alice, mpt.issuanceID(), 100, bobPub, issuerPub, bobSk.x),
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
    }

private:
    void
    testConvertSuccess(FeatureBitset features);
    void
    testMergeInbox(FeatureBitset features);
    void
    testSend(FeatureBitset features);

    static json::Value
    sendJV(
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
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt);

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
    std::optional<cmpt::ECPoint> const& auditorPub)
{
    using namespace cmpt;
    Scalar const kt = Scalar::random();
    Scalar const kd = Scalar::random();
    Scalar const ki = Scalar::random();
    auto const senderCt = ElGamalCiphertext::encrypt(senderPub, amount, kt);
    auto const destCt = ElGamalCiphertext::encrypt(destPub, amount, kd);
    auto const issuerCt = ElGamalCiphertext::encrypt(issuerPub, amount, ki);

    Scalar const ra = Scalar::random();
    auto const [rangeAmount, amountCommit] = RangeProof::prove(amount, ra, 63);
    auto const linkAmount =
        LinkageProof::prove(senderSecret, amount, ra, senderCt, amountCommit);

    auto const postDebit = senderSpending - senderCt;
    Scalar const rb = Scalar::random();
    auto const [rangeBalance, balanceCommit] = RangeProof::prove(remaining, rb, 63);
    auto const linkBalance =
        LinkageProof::prove(senderSecret, remaining, rb, postDebit, balanceCommit);

    auto const peqDest = PlaintextEqualityProof::prove(
        senderPub, destPub, amount, kt, kd, senderCt, destCt);
    auto const peqIssuer = PlaintextEqualityProof::prove(
        senderPub, issuerPub, amount, kt, ki, senderCt, issuerCt);

    // Optional auditor mirror: a fresh ciphertext plus its equality proof,
    // serialized between the issuer proof and the linkage proofs.
    std::optional<ElGamalCiphertext> auditorCt;
    std::optional<PlaintextEqualityProof> peqAuditor;
    if (auditorPub)
    {
        Scalar const ka = Scalar::random();
        auditorCt = ElGamalCiphertext::encrypt(*auditorPub, amount, ka);
        peqAuditor = PlaintextEqualityProof::prove(
            senderPub, *auditorPub, amount, kt, ka, senderCt, *auditorCt);
    }

    Blob bundle;
    auto append = [&](auto const& a) {
        bundle.insert(bundle.end(), a.begin(), a.end());
    };
    append(peqDest.serialize());
    append(peqIssuer.serialize());
    if (peqAuditor)
        append(peqAuditor->serialize());
    append(linkAmount.serialize());
    append(linkBalance.serialize());
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
        env(convertJV(bob, id, 400, bobPub, issuerPub, bobSk.x));
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

        auto jv = convertJV(bob, mpt.issuanceID(), 400, bobPub, issuerPub, bobSk.x);
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
        env(convertJV(bob, mpt.issuanceID(), 2000, bobPub, issuerPub, bobSk.x),
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
        env(convertJV(bob, id, 400, bobPub, issuerPub, bobSk.x, auditorPub));
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
                bob, mpt.issuanceID(), 400, bobPub, issuerPub, bobSk.x, auditorPub),
            Ter(tecNO_PERMISSION));
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

        env(convertJV(bob, id, 400, bobPub, issuerPub, bobSk.x));
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
        env(convertJV(bob, id, 1000, bobPub, issuerPub, bobSk.x));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        // carol opts in with a zero-amount conversion.
        env(convertJV(carol, id, 0, carolPub, issuerPub, carolSk.x));
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
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
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
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        auto proof = *strUnHex(jv[sfZKProof].asString());
        proof[0] ^= 0x01;
        jv[sfZKProof] = strHex(proof);
        env(jv, Ter(tecBAD_PROOF));
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
        env(convertJV(bob, id, 1000, bobPub, issuerPub, bobSk.x, auditorPub));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        env(convertJV(carol, id, 0, carolPub, issuerPub, carolSk.x, auditorPub));
        env.close();
        env(mergeJV(carol, id));
        env.close();

        env(sendJV(
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
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
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
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
                bob, carol, mpt.issuanceID(), 1, 0, bobSk.x, bobPub, carolPub,
                issuerPub, cmpt::ElGamalCiphertext::encryptZero()),
            Ter(temDISABLED));
    }
}

void
testDepositAuth(FeatureBitset features)
{
    testcase("DepositAuth and Credentials enforcement");
    using namespace jtx;

    Account const alice("alice");
    Account const bob("bob");
    Account const carol("carol");
    Account const issuer("issuer");

    auto const issuerSk = cmpt::ElGamalSecretKey::random();
    auto const issuerPub = issuerSk.publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();
    auto const carolSk = cmpt::ElGamalSecretKey::random();
    auto const carolPub = carolSk.publicKey();

    std::string const credType = "abcdefgh";

    auto setup = [&](Env& env) -> MPTID {
        MPTTester mpt(env, alice, {.holders = {bob, carol}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        auto const id = mpt.issuanceID();
        env(mpt::setEncryptionKey(alice, id, issuerPub));
        env.close();
        mpt.authorize({.account = bob});
        mpt.authorize({.account = carol});
        env(mpt::setEncryptionKey(bob, id, bobPub));
        env(mpt::setEncryptionKey(carol, id, carolPub));
        env.close();
        env(convertJV(bob, id, 1000, bobPub, issuerPub, bobSk.x));
        env.close();
        return id;
    };

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(fset(carol, asfDepositAuth));
        env.close();
        auto jv = sendJV(
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
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
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        env(jv);
        env.close();
        BEAST_EXPECT(env.balance(carol, id) == 400);
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(credentials::create(bob, issuer, credType));
        env.close();
        env(credentials::accept(bob, issuer, credType));
        env.close();
        auto const jv = credentials::ledgerEntry(env, bob, issuer, credType);
        std::string const credIdx = jv[jss::result][jss::index].asString();
        env(fset(carol, asfDepositAuth));
        env.close();
        auto jsend = sendJV(
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jsend[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jsend[sfCredentialIDs.jsonName].append(credIdx);
        env(jsend, Ter(tecNO_PERMISSION));
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(credentials::create(bob, issuer, credType));
        env.close();
        env(credentials::accept(bob, issuer, credType));
        env.close();
        auto const jv = credentials::ledgerEntry(env, bob, issuer, credType);
        std::string const credIdx = jv[jss::result][jss::index].asString();
        env(fset(carol, asfDepositAuth));
        env.close();
        env(deposit::authCredentials(carol, {{.issuer = issuer, .credType = credType}}));
        env.close();
        auto jsend = sendJV(
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        jsend[sfCredentialIDs.jsonName] = json::ValueType::Array;
        jsend[sfCredentialIDs.jsonName].append(credIdx);
        env(jsend);
        env.close();
        BEAST_EXPECT(env.balance(carol, id) == 400);
    }

    {
        Env env{*this, features};
        auto const id = setup(env);
        env(fset(carol, asfDepositAuth));
        env.close();
        env(deposit::authCredentials(carol, {{.issuer = issuer, .credType = credType}}));
        env.close();
        auto jsend = sendJV(
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
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
            bob, carol, id, 400, 600, bobSk.x, bobPub, carolPub, issuerPub,
            readSpending(env, id, bob));
        env(jsend);
        env.close();
        BEAST_EXPECT(env.balance(carol, id) == 400);
    }
}

void
run() override
{
    using namespace jtx;
    auto const all = supported_amendments();
    testConvert(all);
    testSend(all);
    testDepositAuth(all);
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPTSendPath, app, xrpl);

}  // namespace xrpl::test
