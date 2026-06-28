#include <test/jtx.h>
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

namespace xrpl::test {

class ConfidentialMPTConvertBack_test : public beast::unit_test::Suite
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

    // Build a ConfidentialMPTConvert JSON registering a new holder key.
    static json::Value
    convertJV(
        jtx::Account const& account,
        MPTID const& id,
        std::uint64_t amount,
        cmpt::ECPoint const& holderPub,
        cmpt::ECPoint const& issuerPub,
        cmpt::Scalar const& holderSecret,
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt)
    {
        cmpt::Scalar const k = cmpt::Scalar::random();
        json::Value jv;
        jv[jss::TransactionType] = "ConfidentialMPTConvert";
        jv[jss::Account] = account.human();
        jv[sfMPTokenIssuanceID] = to_string(id);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfHolderEncryptedAmount] =
            hexOf(cmpt::ElGamalCiphertext::encrypt(holderPub, amount, k).serialize());
        jv[sfIssuerEncryptedAmount] =
            hexOf(cmpt::ElGamalCiphertext::encrypt(issuerPub, amount, k).serialize());
        jv[sfBlindingFactor] = hexOf(k.bytes());
        if (auditorPub)
            jv[sfAuditorEncryptedAmount] =
                hexOf(cmpt::ElGamalCiphertext::encrypt(*auditorPub, amount, k).serialize());
        jv[sfHolderEncryptionKey] = hexOf(holderPub.serialize());
        jv[sfZKProof] =
            hexOf(cmpt::SchnorrProof::prove(holderSecret, holderPub).serialize());
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

    static cmpt::ElGamalCiphertext
    readSpending(jtx::Env& env, MPTID const& id, jtx::Account const& a)
    {
        auto const sle = env.le(keylet::mptoken(id, a.id()));
        auto const b = sle->getFieldVL(sfConfidentialBalanceSpending);
        return *cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()});
    }

    // Build a ConfidentialMPTConvertBack JSON. The withdrawn amount is public
    // (verified deterministically via the shared blinding factor); the ZKProof
    // bundle (816 bytes) proves the post-debit spending balance (== remaining) is
    // valid and non-negative through a compact sigma proof (128 B) plus a range
    // proof (688 B, implicit 63-bit width).
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
        cmpt::ElGamalCiphertext const& spending,
        std::optional<cmpt::ECPoint> const& auditorPub = std::nullopt)
    {
        using namespace cmpt;
        Scalar const k = Scalar::random();
        auto const holderCt = ElGamalCiphertext::encrypt(holderPub, amount, k);
        auto const issuerCt = ElGamalCiphertext::encrypt(issuerPub, amount, k);

        auto const postDebit = spending - holderCt;
        Scalar const rb = Scalar::random();
        auto const [rangeBalance, balanceCommit] = RangeProof::prove(remaining, rb, 63);
        // Bind the proof to the transaction the holder is about to submit; the
        // verifier recomputes the same context from the tx account, sequence,
        // and the pre-transaction confidential balance version. env.seq(account)
        // equals the sequence jtx will autofill; an absent MPToken means ver 0.
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
        // Range proof serialization: strip the leading width byte to match
        // mpt-crypto's implicit-width Bulletproof encoding.
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
        if (auditorPub)
            jv[sfAuditorEncryptedAmount] =
                hexOf(ElGamalCiphertext::encrypt(*auditorPub, amount, k).serialize());
        jv[sfBalanceCommitment] = hexOf(balanceCommit.serialize());
        jv[sfZKProof] = strHex(bundle);
        return jv;
    }

    void
    testConvertBack(FeatureBitset features);

public:
    void
    run() override
    {
        testConvertBack(jtx::testableAmendments());
    }
};

void
ConfidentialMPTConvertBack_test::testConvertBack(FeatureBitset features)
{
    testcase("ConfidentialMPTConvertBack");
    using namespace jtx;

    Account const alice("alice");  // issuer
    Account const bob("bob");      // holder
    auto const issuerPub = cmpt::ElGamalSecretKey::random().publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    // Set up a confidential issuance and fund bob's spending balance with
    // `funded` confidential units (converted from public, then merged).
    auto setup = [&](Env& env,
                     std::uint64_t funded,
                     std::optional<cmpt::ECPoint> const& auditorPub =
                         std::nullopt) -> MPTID {
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        if (auditorPub)
            mpt.set(
                {.account = alice,
                 .issuerEncryptionKey = rawStr(issuerPub.serialize()),
                 .auditorEncryptionKey = rawStr(auditorPub->serialize())});
        else
            mpt.set(
                {.account = alice,
                 .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        auto const id = mpt.issuanceID();
        env(convertJV(bob, id, funded, bobPub, issuerPub, bobSk.x, auditorPub));
        env.close();
        env(mergeJV(bob, id));
        env.close();
        return id;
    };

    // Amendment-gated: the transaction type is unavailable without the
    // ConfidentialMPT amendment.
    {
        Env env{*this, features - featureConfidentialMPT};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        env(convertBackJV(
                env, bob, mpt.issuanceID(), 1, 0, bobSk.x, bobPub, issuerPub,
                cmpt::ElGamalCiphertext::encryptZero()),
            Ter(temDISABLED));
    }

    // Issuer cannot convert back its own issuance.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        env(convertBackJV(
                env, alice, mpt.issuanceID(), 1, 0, bobSk.x, bobPub, issuerPub,
                cmpt::ElGamalCiphertext::encryptZero()),
            Ter(temMALFORMED));
    }

    // A zero withdrawal is rejected: the amount must be strictly positive.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(convertBackJV(
                env, bob, id, 0, 400, bobSk.x, bobPub, issuerPub,
                readSpending(env, id, bob)),
            Ter(temBAD_AMOUNT));
    }

    // Capability-flag rejection: the issuance does not allow confidential
    // amounts.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(convertBackJV(
                env, bob, mpt.issuanceID(), 100, 0, bobSk.x, bobPub, issuerPub,
                cmpt::ElGamalCiphertext::encryptZero()),
            Ter(tecNO_PERMISSION));
    }

    // Success: public balance credited, COA decremented, spending balance
    // debited and version bumped, public OutstandingAmount unchanged.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);

        auto const before = env.le(keylet::mptoken(id, bob.id()))
                                ->getFieldU32(sfConfidentialBalanceVersion);
        env(convertBackJV(
            env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
            readSpending(env, id, bob)));
        env.close();

        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU64(sfMPTAmount) == 750);
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == before + 1);
        BEAST_EXPECT(readSpending(env, id, bob).decrypt(bobSk.x, 2000) == 250);

        auto const iss = env.le(keylet::mptIssuance(id));
        BEAST_EXPECT(iss && iss->getFieldU64(sfConfidentialOutstandingAmount) == 250);
        BEAST_EXPECT(iss && iss->getFieldU64(sfOutstandingAmount) == 1000);
    }

    // Withdrawing more than the confidential supply fails.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(convertBackJV(
                env, bob, id, 500, 0, bobSk.x, bobPub, issuerPub,
                readSpending(env, id, bob)),
            Ter(tecINSUFFICIENT_FUNDS));
    }

    // A tampered proof bundle is rejected.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        auto jv = convertBackJV(
            env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
            readSpending(env, id, bob));
        auto proof = *strUnHex(jv[sfZKProof].asString());
        proof[0] ^= 0x01;
        jv[sfZKProof] = strHex(proof);
        env(jv, Ter(tecBAD_PROOF));
    }

    // A tampered amount (ciphertext does not match the public amount) is
    // rejected by deterministic verification.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        auto jv = convertBackJV(
            env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
            readSpending(env, id, bob));
        jv[sfMPTAmount] = std::to_string(151);  // mismatch
        env(jv, Ter(tecBAD_PROOF));
    }

    // Audited issuance: a valid auditor ciphertext is accepted and the auditor
    // mirror is debited in lockstep.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        auto const id = setup(env, 400, auditorPub);
        env(convertBackJV(
            env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
            readSpending(env, id, bob), auditorPub));
        env.close();
        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->isFieldPresent(sfAuditorEncryptedBalance));
        BEAST_EXPECT(tok && tok->getFieldU64(sfMPTAmount) == 750);
    }

    // Audited issuance: a missing auditor ciphertext is rejected.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        auto const id = setup(env, 400, auditorPub);
        env(convertBackJV(
                env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
                readSpending(env, id, bob)),
            Ter(tecNO_PERMISSION));
    }

    // Non-audited issuance must reject an attached auditor ciphertext: an
    // issuance with no auditor key may not accept an unverified auditor mirror.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        env(convertBackJV(
                env, bob, id, 150, 250, bobSk.x, bobPub, issuerPub,
                readSpending(env, id, bob), auditorPub),
            Ter(tecNO_PERMISSION));
    }
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPTConvertBack, app, xrpl);

}  // namespace xrpl::test
