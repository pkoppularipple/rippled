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

class ConfidentialMPTClawback_test : public beast::unit_test::Suite
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
    readCt(jtx::Env& env, MPTID const& id, jtx::Account const& a, SField const& f)
    {
        auto const sle = env.le(keylet::mptoken(id, a.id()));
        if (!sle || !sle->isFieldPresent(f))
            return cmpt::ElGamalCiphertext::encryptZero();
        auto const b = sle->getFieldVL(f);
        return *cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()});
    }

    // Build a ConfidentialMPTClawback JSON. The clawed-back amount is public; the
    // ZKProof is a single linkage proof binding the holder's issuer mirror to a
    // commitment the verifier reconstructs from the amount and blinding factor,
    // proving the mirror encrypts exactly that amount through the issuer's key.
    static json::Value
    clawbackJV(
        jtx::Account const& issuer,
        jtx::Account const& holder,
        MPTID const& id,
        std::uint64_t amount,
        cmpt::Scalar const& issuerSecret,
        cmpt::ElGamalCiphertext const& issuerMirror)
    {
        using namespace cmpt;
        Scalar const r = Scalar::random();
        auto const commitment = PedersenCommitment::commit(amount, r);
        auto const proof =
            LinkageProof::prove(issuerSecret, amount, r, issuerMirror, commitment);

        json::Value jv;
        jv[jss::TransactionType] = "ConfidentialMPTClawback";
        jv[jss::Account] = issuer.human();
        jv[sfHolder] = holder.human();
        jv[sfMPTokenIssuanceID] = to_string(id);
        jv[sfMPTAmount] = std::to_string(amount);
        jv[sfBlindingFactor] = hexOf(r.bytes());
        jv[sfZKProof] = hexOf(proof.serialize());
        return jv;
    }

    void
    testClawback(FeatureBitset features);

public:
    void
    run() override
    {
        testClawback(jtx::testableAmendments());
    }
};

void
ConfidentialMPTClawback_test::testClawback(FeatureBitset features)
{
    testcase("ConfidentialMPTClawback");
    using namespace jtx;

    Account const alice("alice");  // issuer
    Account const bob("bob");      // holder
    auto const issuerSk = cmpt::ElGamalSecretKey::random();
    auto const issuerPub = issuerSk.publicKey();
    auto const bobSk = cmpt::ElGamalSecretKey::random();
    auto const bobPub = bobSk.publicKey();

    // Set up a confidential, clawback-enabled issuance and fund bob's spending
    // balance with `funded` confidential units (converted, then merged).
    auto setup = [&](Env& env,
                     std::uint64_t funded,
                     std::optional<cmpt::ECPoint> const& auditorPub =
                         std::nullopt) -> MPTID {
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create(
            {.flags =
                 tfMPTCanTransfer | tfMPTCanConfidentialAmount | tfMPTCanClawback});
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

    auto const zero = cmpt::ElGamalCiphertext::encryptZero();

    // Amendment-gated: the transaction type is unavailable without the
    // ConfidentialMPT amendment.
    {
        Env env{*this, features - featureConfidentialMPT};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanClawback});
        mpt.authorize({.account = bob});
        env(clawbackJV(alice, bob, mpt.issuanceID(), 1, issuerSk.x, zero),
            Ter(temDISABLED));
    }

    // Only the issuer may claw back: a non-issuer account is rejected.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(clawbackJV(bob, bob, id, 400, issuerSk.x, readCt(env, id, bob, sfIssuerEncryptedBalance)),
            Ter(temMALFORMED));
    }

    // The issuer cannot be the clawback target.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(clawbackJV(alice, alice, id, 400, issuerSk.x, zero),
            Ter(temMALFORMED));
    }

    // A zero amount is rejected: the burned balance must be strictly positive.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(clawbackJV(alice, bob, id, 0, issuerSk.x, readCt(env, id, bob, sfIssuerEncryptedBalance)),
            Ter(temBAD_AMOUNT));
    }

    // Capability-flag rejection: the issuance does not allow confidential
    // amounts.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanClawback});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(clawbackJV(alice, bob, mpt.issuanceID(), 100, issuerSk.x, zero),
            Ter(tecNO_PERMISSION));
    }

    // Clawback-flag rejection: the issuance does not allow clawback.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(convertJV(bob, mpt.issuanceID(), 400, bobPub, issuerPub, bobSk.x));
        env.close();
        env(clawbackJV(
                alice, bob, mpt.issuanceID(), 400, issuerSk.x,
                readCt(env, mpt.issuanceID(), bob, sfIssuerEncryptedBalance)),
            Ter(tecNO_PERMISSION));
    }

    // The holder must have an MPToken for the issuance.
    {
        Env env{*this, features};
        Account const carol("carol");
        env.fund(XRP(1000), carol);
        env.close();
        auto const id = setup(env, 400);
        env(clawbackJV(alice, carol, id, 400, issuerSk.x, zero),
            Ter(tecOBJECT_NOT_FOUND));
    }

    // The holder must have initialized confidential state.
    {
        Env env{*this, features};
        MPTTester mpt(env, alice, {.holders = {bob}});
        mpt.create({.flags = tfMPTCanTransfer | tfMPTCanConfidentialAmount | tfMPTCanClawback});
        mpt.set({.account = alice, .issuerEncryptionKey = rawStr(issuerPub.serialize())});
        mpt.authorize({.account = bob});
        mpt.pay(alice, bob, 1000);
        env(clawbackJV(alice, bob, mpt.issuanceID(), 100, issuerSk.x, zero),
            Ter(tecNO_PERMISSION));
    }

    // Clawing back more than the confidential supply fails.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        env(clawbackJV(alice, bob, id, 500, issuerSk.x, readCt(env, id, bob, sfIssuerEncryptedBalance)),
            Ter(tecINSUFFICIENT_FUNDS));
    }

    // A tampered proof is rejected.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        auto jv = clawbackJV(
            alice, bob, id, 400, issuerSk.x, readCt(env, id, bob, sfIssuerEncryptedBalance));
        auto proof = *strUnHex(jv[sfZKProof].asString());
        proof[0] ^= 0x01;
        jv[sfZKProof] = strHex(proof);
        env(jv, Ter(tecBAD_PROOF));
    }

    // An amount that does not match the issuer mirror is rejected: the linkage
    // proof binds the mirror to the disclosed amount.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);
        auto jv = clawbackJV(
            alice, bob, id, 400, issuerSk.x, readCt(env, id, bob, sfIssuerEncryptedBalance));
        jv[sfMPTAmount] = std::to_string(399);  // mismatch
        env(jv, Ter(tecBAD_PROOF));
    }

    // Success: the entire confidential balance is burned, all ciphertexts reset
    // to encrypted zero, the version is bumped, and OA and COA decrease by the
    // burned amount while the public balance is unchanged.
    {
        Env env{*this, features};
        auto const id = setup(env, 400);

        auto const before = env.le(keylet::mptoken(id, bob.id()))
                                ->getFieldU32(sfConfidentialBalanceVersion);
        env(clawbackJV(
            alice, bob, id, 400, issuerSk.x,
            readCt(env, id, bob, sfIssuerEncryptedBalance)));
        env.close();

        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->getFieldU64(sfMPTAmount) == 600);
        BEAST_EXPECT(tok && tok->getFieldU32(sfConfidentialBalanceVersion) == before + 1);
        BEAST_EXPECT(readCt(env, id, bob, sfConfidentialBalanceSpending) == zero);
        BEAST_EXPECT(readCt(env, id, bob, sfConfidentialBalanceInbox) == zero);
        BEAST_EXPECT(readCt(env, id, bob, sfIssuerEncryptedBalance) == zero);

        auto const iss = env.le(keylet::mptIssuance(id));
        BEAST_EXPECT(iss && iss->getFieldU64(sfConfidentialOutstandingAmount) == 0);
        BEAST_EXPECT(iss && iss->getFieldU64(sfOutstandingAmount) == 600);
    }

    // Audited issuance: the auditor mirror is reset to encrypted zero in lockstep.
    {
        Env env{*this, features};
        auto const auditorPub = cmpt::ElGamalSecretKey::random().publicKey();
        auto const id = setup(env, 400, auditorPub);
        env(clawbackJV(
            alice, bob, id, 400, issuerSk.x,
            readCt(env, id, bob, sfIssuerEncryptedBalance)));
        env.close();
        auto const tok = env.le(keylet::mptoken(id, bob.id()));
        BEAST_EXPECT(tok && tok->isFieldPresent(sfAuditorEncryptedBalance));
        BEAST_EXPECT(readCt(env, id, bob, sfAuditorEncryptedBalance) == zero);
    }
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPTClawback, app, xrpl);

}  // namespace xrpl::test
