#include <xrpl/tx/transactors/token/ConfidentialMPTConvertBack.h>

#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
#include <xrpl/protocol/Protocol.h>
#include <xrpl/protocol/SField.h>
#include <xrpl/protocol/STLedgerEntry.h>
#include <xrpl/protocol/STTx.h>
#include <xrpl/protocol/TER.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/XRPAmount.h>
#include <xrpl/tx/Transactor.h>

#include <cstdint>
#include <optional>

namespace xrpl {

namespace {

bool
validCiphertext(std::optional<Slice> const& s)
{
    return s && s->size() == cmpt::kCiphertextSize &&
        cmpt::ElGamalCiphertext::deserialize(*s).has_value();
}

bool
validPoint(std::optional<Slice> const& s)
{
    return s && s->size() == cmpt::kPointSize &&
        cmpt::ECPoint::deserialize(*s).has_value();
}

// Layout of the ZKProof bundle carried by ConfidentialMPTConvertBack: a linkage
// proof binding sfBalanceCommitment to the post-debit spending balance (balance
// ownership and key linkage) followed by a logarithmic aggregated-Bulletproof
// range proof proving the remaining balance is non-negative. This is the same
// encoding the send path uses for its balance half; the range proof is
// self-describing via its leading bit-width byte.
struct ConvertBackProofs
{
    cmpt::LinkageProof linkBalance;
    cmpt::RangeProof rangeBalance;
};

std::optional<ConvertBackProofs>
parseConvertBackProofs(Slice const& in)
{
    constexpr std::size_t link = cmpt::LinkageProof::serializedSize();
    if (in.size() <= link + 1)
        return std::nullopt;

    auto const lb = cmpt::LinkageProof::deserialize(Slice{in.data(), link});
    if (!lb)
        return std::nullopt;

    // The range proof is self-describing: byte 0 is the bit width.
    std::size_t const rem = in.size() - link;
    std::uint8_t const bits = in.data()[link];
    if (bits == 0 || bits > cmpt::RangeProof::kMaxBits)
        return std::nullopt;
    if (rem != cmpt::RangeProof::serializedSize(bits))
        return std::nullopt;
    auto const rb = cmpt::RangeProof::deserialize(Slice{in.data() + link, rem});
    if (!rb)
        return std::nullopt;

    ConvertBackProofs p;
    p.linkBalance = *lb;
    p.rangeBalance = *rb;
    return p;
}

cmpt::ElGamalCiphertext
loadCt(SLE const& sle, SField const& f)
{
    if (sle.isFieldPresent(f))
    {
        auto const b = sle.getFieldVL(f);
        if (auto ct = cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()}))
            return *ct;
    }
    return cmpt::ElGamalCiphertext::encryptZero();
}

}  // namespace

NotTEC
ConfidentialMPTConvertBack::preflight(PreflightContext const& ctx)
{
    // The issuer account cannot convert its own issuance.
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() == ctx.tx[sfAccount])
        return temMALFORMED;

    if (ctx.tx[sfBlindingFactor].size() != cmpt::kScalarSize)
        return temMALFORMED;

    // Ciphertexts must be well-formed curve points.
    if (!validCiphertext(ctx.tx[~sfHolderEncryptedAmount]) ||
        !validCiphertext(ctx.tx[~sfIssuerEncryptedAmount]))
        return temMALFORMED;

    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount) &&
        !validCiphertext(ctx.tx[~sfAuditorEncryptedAmount]))
        return temMALFORMED;

    if (!validPoint(ctx.tx[~sfBalanceCommitment]))
        return temMALFORMED;

    // The withdrawn amount is public and must be strictly positive.
    std::uint64_t const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(id));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanConfidentialAmount))
        return tecNO_PERMISSION;

    // The issuance must carry a registered issuer encryption key (Slice 5).
    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const sleToken = ctx.view.read(keylet::mptoken(id, ctx.tx[sfAccount]));
    if (!sleToken)
        return tecOBJECT_NOT_FOUND;

    // The holder must already be initialized for confidential balances.
    if (!sleToken->isFieldPresent(sfHolderEncryptionKey) ||
        !sleToken->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;

    // The auditor ciphertext is mandatory when an auditor key is configured,
    // and forbidden otherwise: a non-audited issuance must not accept an
    // unverified auditor mirror.
    bool const hasAuditor = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (hasAuditor != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    MPTIssue const mptIssue{id};
    if (isFrozen(ctx.view, ctx.tx[sfAccount], mptIssue))
        return tecFROZEN;

    std::uint64_t const amount = ctx.tx[sfMPTAmount];

    // The confidential supply must cover the requested withdrawal.
    std::uint64_t const coa =
        sleIssuance->isFieldPresent(sfConfidentialOutstandingAmount)
        ? sleIssuance->getFieldU64(sfConfidentialOutstandingAmount)
        : 0u;
    if (coa < amount)
        return tecINSUFFICIENT_FUNDS;

    // Deterministic ciphertext verification: with the disclosed blinding factor
    // and the public amount, every ciphertext must reconstruct exactly.
    cmpt::Scalar const blind{ctx.tx[sfBlindingFactor]};

    auto const holderKeyBlob = sleToken->getFieldVL(sfHolderEncryptionKey);
    auto const holderKey =
        cmpt::ECPoint::deserialize(Slice{holderKeyBlob.data(), holderKeyBlob.size()});
    auto const issuerKeyBlob = sleIssuance->getFieldVL(sfIssuerEncryptionKey);
    auto const issuerKey =
        cmpt::ECPoint::deserialize(Slice{issuerKeyBlob.data(), issuerKeyBlob.size()});
    if (!holderKey || holderKey->isInfinity() || !issuerKey || issuerKey->isInfinity())
        return tecBAD_PROOF;

    auto verifyCt = [&](cmpt::ECPoint const& key, Slice const& provided) -> bool {
        auto const want = cmpt::ElGamalCiphertext::encrypt(key, amount, blind);
        auto const got = cmpt::ElGamalCiphertext::deserialize(provided);
        return got && (*got == want);
    };

    if (!verifyCt(*holderKey, ctx.tx[sfHolderEncryptedAmount]) ||
        !verifyCt(*issuerKey, ctx.tx[sfIssuerEncryptedAmount]))
        return tecBAD_PROOF;

    if (hasAuditor)
    {
        auto const auditorKeyBlob = sleIssuance->getFieldVL(sfAuditorEncryptionKey);
        auto const auditorKey = cmpt::ECPoint::deserialize(
            Slice{auditorKeyBlob.data(), auditorKeyBlob.size()});
        if (!auditorKey || auditorKey->isInfinity() ||
            !verifyCt(*auditorKey, ctx.tx[sfAuditorEncryptedAmount]))
            return tecBAD_PROOF;
    }

    // Post-debit spending balance must be valid and non-negative. The balance
    // ciphertext is debited homomorphically, and the holder proves through
    // knowledge of their secret key that sfBalanceCommitment encodes the same
    // remaining balance; the range proof then proves it is non-negative.
    auto const balanceCommit =
        *cmpt::PedersenCommitment::deserialize(ctx.tx[sfBalanceCommitment]);
    auto const holderCt =
        *cmpt::ElGamalCiphertext::deserialize(ctx.tx[sfHolderEncryptedAmount]);
    auto const postDebit =
        loadCt(*sleToken, sfConfidentialBalanceSpending) - holderCt;

    auto const proofs = parseConvertBackProofs(ctx.tx[sfZKProof]);
    if (!proofs)
        return tecBAD_PROOF;

    if (!proofs->linkBalance.verify(*holderKey, postDebit, balanceCommit) ||
        !proofs->rangeBalance.verify(balanceCommit))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvertBack::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = view().peek(keylet::mptIssuance(id));
    auto const sleToken = view().peek(keylet::mptoken(id, accountID_));
    if (!sleIssuance || !sleToken)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    // Mirror the auditor ciphertext only when the issuance actually has an
    // auditor key, not merely when the tx field is present.
    bool const hasAuditor =
        sleIssuance->isFieldPresent(sfAuditorEncryptionKey) &&
        ctx_.tx.isFieldPresent(sfAuditorEncryptedAmount);
    auto txCt = [&](auto const& f) {
        return *cmpt::ElGamalCiphertext::deserialize(ctx_.tx[f]);
    };
    auto write = [&](SField const& f, cmpt::ElGamalCiphertext const& ct) {
        auto const s = ct.serialize();
        sleToken->setFieldVL(f, Slice{s.data(), s.size()});
    };

    // Homomorphically debit the spending balance and the issuer (and auditor)
    // mirrors by the converted amount.
    write(
        sfConfidentialBalanceSpending,
        loadCt(*sleToken, sfConfidentialBalanceSpending) - txCt(sfHolderEncryptedAmount));
    write(
        sfIssuerEncryptedBalance,
        loadCt(*sleToken, sfIssuerEncryptedBalance) - txCt(sfIssuerEncryptedAmount));
    if (hasAuditor)
        write(
            sfAuditorEncryptedBalance,
            loadCt(*sleToken, sfAuditorEncryptedBalance) - txCt(sfAuditorEncryptedAmount));

    // The spending balance changed, so the version must be bumped.
    std::uint32_t const v = sleToken->isFieldPresent(sfConfidentialBalanceVersion)
        ? sleToken->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    sleToken->setFieldU32(
        sfConfidentialBalanceVersion, v == 0xFFFFFFFFu ? 0u : v + 1u);

    std::uint64_t const amount = ctx_.tx[sfMPTAmount];

    // Credit the public balance; the public OutstandingAmount is unchanged.
    (*sleToken)[sfMPTAmount] = sleToken->getFieldU64(sfMPTAmount) + amount;

    // Decrease the confidential outstanding amount (ΔCOA == -ΔMPTAmount).
    std::uint64_t const coa =
        sleIssuance->isFieldPresent(sfConfidentialOutstandingAmount)
        ? sleIssuance->getFieldU64(sfConfidentialOutstandingAmount)
        : 0u;
    (*sleIssuance)[sfConfidentialOutstandingAmount] = coa - amount;

    view().update(sleToken);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvertBack::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
}

bool
ConfidentialMPTConvertBack::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
