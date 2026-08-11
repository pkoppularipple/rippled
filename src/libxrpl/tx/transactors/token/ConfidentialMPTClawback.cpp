#include <xrpl/tx/transactors/token/ConfidentialMPTClawback.h>

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

XRPAmount
ConfidentialMPTClawback::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cmpt::kConfidentialFeeMultiplier *
        Transactor::calculateBaseFee(view, tx);
}

NotTEC
ConfidentialMPTClawback::preflight(PreflightContext const& ctx)
{
    // Clawback is issuer-only: the account must be the issuer of the issuance.
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() != ctx.tx[sfAccount])
        return temMALFORMED;

    // The issuer cannot hold a confidential balance, so it cannot be the target.
    if (ctx.tx[sfHolder] == ctx.tx[sfAccount])
        return temMALFORMED;

    // The ZKProof carries exactly one compact clawback proof (64 B).
    if (ctx.tx[sfZKProof].size() != cmpt::CompactClawbackProof::serializedSize())
        return temMALFORMED;

    // The clawed-back amount is the holder's entire confidential balance; it is
    // public and must be strictly positive.
    std::uint64_t const amount = ctx.tx[sfMPTAmount];
    if (amount == 0 || amount > kMaxMpTokenAmount)
        return temBAD_AMOUNT;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(id));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanConfidentialAmount))
        return tecNO_PERMISSION;

    // The issuance must opt into clawback, exactly as the public Clawback path.
    if (!sleIssuance->isFlag(lsfMPTCanClawback))
        return tecNO_PERMISSION;

    // The issuance must carry a registered issuer encryption key (Slice 5).
    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const sleToken = ctx.view.read(keylet::mptoken(id, ctx.tx[sfHolder]));
    if (!sleToken)
        return tecOBJECT_NOT_FOUND;

    // The holder must already be initialized for confidential balances.
    if (!sleToken->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;

    std::uint64_t const amount = ctx.tx[sfMPTAmount];

    // The confidential supply must cover the burned balance.
    std::uint64_t const coa =
        sleIssuance->isFieldPresent(sfConfidentialOutstandingAmount)
        ? sleIssuance->getFieldU64(sfConfidentialOutstandingAmount)
        : 0u;
    if (coa < amount)
        return tecINSUFFICIENT_FUNDS;

    // The public supply must likewise cover the burn: sfOutstandingAmount is
    // always present on an issuance, and guarding it here ensures doApply()'s
    // `oa - amount` can never underflow on an inconsistent issuance.
    if (sleIssuance->getFieldU64(sfOutstandingAmount) < amount)
        return tecINSUFFICIENT_FUNDS;

    auto const issuerKeyBlob = sleIssuance->getFieldVL(sfIssuerEncryptionKey);
    auto const issuerKey =
        cmpt::ECPoint::deserialize(Slice{issuerKeyBlob.data(), issuerKeyBlob.size()});
    if (!issuerKey || issuerKey->isInfinity())
        return tecBAD_PROOF;

    // The issuer proves, through knowledge of its secret key, that the issuer
    // mirror (the holder's full balance encrypted under the issuer key) encrypts
    // exactly the disclosed amount. Compact clawback proof verifies:
    //   P_iss = sk_iss*G  and  C2 - m*G = sk_iss*C1.
    auto const issuerMirror = loadCt(*sleToken, sfIssuerEncryptedBalance);

    // Bind the proof to this transaction for replay/domain separation: the
    // context_id commits to the issuer, issuance, transaction sequence, and the
    // targeted holder, matching the reference mpt-crypto clawback preimage. Use
    // the SeqProxy value rather than sfSequence directly so ticketed
    // transactions (sfSequence == 0) bind to their unique ticket number; a
    // ticket and a sequence can never collide on the same account.
    auto const contextId = cmpt::clawbackContextId(
        ctx.tx[sfAccount], id, ctx.tx.getSeqValue(), ctx.tx[sfHolder]);

    auto const proof = cmpt::CompactClawbackProof::deserialize(ctx.tx[sfZKProof]);
    if (!proof ||
        !proof->verify(
            amount,
            *issuerKey,
            issuerMirror,
            Slice{contextId.data(), contextId.size()}))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTClawback::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = view().peek(keylet::mptIssuance(id));
    auto const sleToken = view().peek(keylet::mptoken(id, ctx_.tx[sfHolder]));
    if (!sleIssuance || !sleToken)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const zero = cmpt::ElGamalCiphertext::encryptZero();
    auto write = [&](SField const& f) {
        auto const s = zero.serialize();
        sleToken->setFieldVL(f, Slice{s.data(), s.size()});
    };

    // The entire confidential balance is burned: reset every ciphertext to the
    // canonical encrypted zero. Encrypted zero is key-independent, so the issuer
    // and (when present) auditor mirrors reset correctly without any disclosed
    // ciphertext.
    write(sfConfidentialBalanceInbox);
    write(sfConfidentialBalanceSpending);
    write(sfIssuerEncryptedBalance);
    if (sleToken->isFieldPresent(sfAuditorEncryptedBalance))
        write(sfAuditorEncryptedBalance);

    // The spending balance changed, so the version must be bumped.
    std::uint32_t const v = sleToken->isFieldPresent(sfConfidentialBalanceVersion)
        ? sleToken->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    sleToken->setFieldU32(
        sfConfidentialBalanceVersion, v == 0xFFFFFFFFu ? 0u : v + 1u);

    std::uint64_t const amount = ctx_.tx[sfMPTAmount];

    // Burn semantics: both the public OutstandingAmount and the confidential
    // outstanding amount decrease by the revealed amount; nothing is credited to
    // any account (ΔOA == ΣΔMPT + ΔCOA holds as -M == 0 + -M).
    std::uint64_t const oa = sleIssuance->getFieldU64(sfOutstandingAmount);
    (*sleIssuance)[sfOutstandingAmount] = oa - amount;

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
ConfidentialMPTClawback::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
}

bool
ConfidentialMPTClawback::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
