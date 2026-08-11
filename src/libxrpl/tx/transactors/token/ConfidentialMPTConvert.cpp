#include <xrpl/tx/transactors/token/ConfidentialMPTConvert.h>

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

namespace xrpl {

namespace {

// A serialized confidential key is a single 33-byte compressed point.
constexpr std::size_t kConfidentialKeySize = cmpt::kPointSize;

bool
validCiphertext(std::optional<Slice> const& s)
{
    return s && s->size() == cmpt::kCiphertextSize &&
        cmpt::ElGamalCiphertext::deserialize(*s).has_value();
}

}  // namespace

XRPAmount
ConfidentialMPTConvert::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return confidentialBaseFee(view, tx);
}

NotTEC
ConfidentialMPTConvert::preflight(PreflightContext const& ctx)
{
    // Self-conversion only: the issuer account cannot convert its own issuance.
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() == ctx.tx[sfAccount])
        return temMALFORMED;

    auto const holderKey = ctx.tx[~sfHolderEncryptionKey];
    auto const zkProof = ctx.tx[~sfZKProof];

    // The Schnorr proof is required exactly when a new holder key is registered.
    if (holderKey.has_value() != zkProof.has_value())
        return temMALFORMED;

    if (holderKey && holderKey->size() != kConfidentialKeySize)
        return temMALFORMED;

    if (zkProof && zkProof->size() != cmpt::SchnorrProof::kSize)
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

    if (ctx.tx[sfMPTAmount] > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::preclaim(PreclaimContext const& ctx)
{
    auto const mptIssuanceID = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(mptIssuanceID));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanConfidentialAmount))
        return tecNO_PERMISSION;

    // The issuance must carry a registered issuer encryption key (Slice 5).
    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    // The auditor ciphertext is mandatory when an auditor key is configured,
    // and forbidden otherwise: a non-audited issuance must not accept an
    // unverified auditor mirror.
    bool const hasAuditor = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (hasAuditor != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    auto const sleToken =
        ctx.view.read(keylet::mptoken(mptIssuanceID, ctx.tx[sfAccount]));
    if (!sleToken)
        return tecOBJECT_NOT_FOUND;

    bool const txKey = ctx.tx.isFieldPresent(sfHolderEncryptionKey);
    bool const ledgerKey = sleToken->isFieldPresent(sfHolderEncryptionKey);
    if (txKey && ledgerKey)
        return tecDUPLICATE;
    if (!txKey && !ledgerKey)
        return tecNO_PERMISSION;

    std::uint64_t const amount = ctx.tx[sfMPTAmount];
    if (sleToken->getFieldU64(sfMPTAmount) < amount)
        return tecINSUFFICIENT_FUNDS;

    // Deterministic ciphertext verification: with the disclosed blinding factor
    // and the public amount, every ciphertext must reconstruct exactly.
    cmpt::Scalar const blind{ctx.tx[sfBlindingFactor]};

    Blob holderKeyBlob;
    if (txKey)
    {
        auto const k = ctx.tx[sfHolderEncryptionKey];
        holderKeyBlob.assign(k.data(), k.data() + k.size());
    }
    else
    {
        holderKeyBlob = sleToken->getFieldVL(sfHolderEncryptionKey);
    }
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

    // A newly registered holder key must be proven via the Schnorr proof. Bind
    // the proof to this transaction so it cannot be replayed: the context_id
    // commits to the converting account, the issuance, and the transaction
    // sequence, matching the reference mpt-crypto convert preimage. Use the
    // SeqProxy value rather than sfSequence directly so ticketed transactions
    // (sfSequence == 0) bind to their unique ticket number.
    if (txKey)
    {
        auto const contextId = cmpt::convertContextId(
            ctx.tx[sfAccount], mptIssuanceID, ctx.tx.getSeqValue());

        auto const zk = cmpt::SchnorrProof::deserialize(ctx.tx[sfZKProof]);
        if (!zk ||
            !zk->verify(*holderKey, Slice{contextId.data(), contextId.size()}))
            return tecBAD_PROOF;
    }

    return tesSUCCESS;
}

TER
ConfidentialMPTConvert::doApply()
{
    auto const mptIssuanceID = ctx_.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = view().peek(keylet::mptIssuance(mptIssuanceID));
    auto const sleToken = view().peek(keylet::mptoken(mptIssuanceID, accountID_));
    if (!sleIssuance || !sleToken)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto readCt = [&](SField const& f) -> cmpt::ElGamalCiphertext {
        if (sleToken->isFieldPresent(f))
        {
            auto const b = sleToken->getFieldVL(f);
            if (auto ct = cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()}))
                return *ct;
        }
        return cmpt::ElGamalCiphertext::encryptZero();
    };
    auto writeCt = [&](SField const& f, cmpt::ElGamalCiphertext const& ct) {
        auto const s = ct.serialize();
        sleToken->setFieldVL(f, Slice{s.data(), s.size()});
    };
    auto txCt = [&](auto const& f) {
        return *cmpt::ElGamalCiphertext::deserialize(ctx_.tx[f]);
    };

    // Register the holder key and initialize confidential state on first use.
    if (ctx_.tx.isFieldPresent(sfHolderEncryptionKey))
    {
        sleToken->setFieldVL(sfHolderEncryptionKey, ctx_.tx[sfHolderEncryptionKey]);
        if (!sleToken->isFieldPresent(sfConfidentialBalanceSpending))
        {
            writeCt(
                sfConfidentialBalanceSpending,
                cmpt::ElGamalCiphertext::encryptZero());
            sleToken->setFieldU32(sfConfidentialBalanceVersion, 0u);
        }
    }

    // Credit the converted amount to the inbox and issuer mirror (and auditor
    // mirror when present). Convert never touches the spending balance, so the
    // version is not changed here.
    writeCt(
        sfConfidentialBalanceInbox,
        readCt(sfConfidentialBalanceInbox) + txCt(sfHolderEncryptedAmount));
    writeCt(
        sfIssuerEncryptedBalance,
        readCt(sfIssuerEncryptedBalance) + txCt(sfIssuerEncryptedAmount));
    if (sleIssuance->isFieldPresent(sfAuditorEncryptionKey) &&
        ctx_.tx.isFieldPresent(sfAuditorEncryptedAmount))
        writeCt(
            sfAuditorEncryptedBalance,
            readCt(sfAuditorEncryptedBalance) + txCt(sfAuditorEncryptedAmount));

    std::uint64_t const amount = ctx_.tx[sfMPTAmount];

    // Debit the public balance; the public OutstandingAmount is unchanged. The
    // proxy assignment drops sfMPTAmount when it reaches its default of zero
    // (it is a kSmdDefault field and may not be stored explicitly as default).
    (*sleToken)[sfMPTAmount] = sleToken->getFieldU64(sfMPTAmount) - amount;

    // Increase the confidential outstanding amount (ΔCOA == -ΔMPTAmount).
    std::uint64_t const coa = sleIssuance->isFieldPresent(sfConfidentialOutstandingAmount)
        ? sleIssuance->getFieldU64(sfConfidentialOutstandingAmount)
        : 0u;
    (*sleIssuance)[sfConfidentialOutstandingAmount] = coa + amount;

    view().update(sleToken);
    view().update(sleIssuance);
    return tesSUCCESS;
}

void
ConfidentialMPTConvert::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
}

bool
ConfidentialMPTConvert::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
