#include <xrpl/tx/transactors/token/ConfidentialMPTSend.h>

#include <xrpl/ledger/helpers/CredentialHelpers.h>
#include <xrpl/ledger/helpers/MPTokenHelpers.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/LedgerFormats.h>
#include <xrpl/protocol/MPTIssue.h>
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

bool
ConfidentialMPTSend::checkExtraFeatures(PreflightContext const& ctx)
{
    return !ctx.tx.isFieldPresent(sfCredentialIDs) || ctx.rules.enabled(featureCredentials);
}

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

// Layout of the ZKProof bundle carried by ConfidentialMPTSend: the
// plaintext-equality and linkage sigma proofs followed by two logarithmic
// aggregated-Bulletproof range proofs (one for the transferred amount, one for
// the remaining spending balance). Each range proof is self-describing via its
// leading bit-width byte.
struct SendProofs
{
    cmpt::PlaintextEqualityProof peqDest;
    cmpt::PlaintextEqualityProof peqIssuer;
    std::optional<cmpt::PlaintextEqualityProof> peqAuditor;
    cmpt::LinkageProof linkAmount;
    cmpt::LinkageProof linkBalance;
    cmpt::RangeProof rangeAmount;
    cmpt::RangeProof rangeBalance;
};

std::optional<SendProofs>
parseSendProofs(Slice const& in, bool hasAuditor)
{
    constexpr std::size_t peq = cmpt::PlaintextEqualityProof::serializedSize();
    constexpr std::size_t link = cmpt::LinkageProof::serializedSize();
    std::size_t const fixed = 2 * peq + (hasAuditor ? peq : 0) + 2 * link;
    if (in.size() < fixed + 2)
        return std::nullopt;

    auto sub = [&](std::size_t off, std::size_t len) {
        return Slice{in.data() + off, len};
    };

    SendProofs p;
    std::size_t off = 0;
    auto pd = cmpt::PlaintextEqualityProof::deserialize(sub(off, peq));
    off += peq;
    auto pi = cmpt::PlaintextEqualityProof::deserialize(sub(off, peq));
    off += peq;
    if (!pd || !pi)
        return std::nullopt;
    p.peqDest = *pd;
    p.peqIssuer = *pi;
    if (hasAuditor)
    {
        auto pa = cmpt::PlaintextEqualityProof::deserialize(sub(off, peq));
        off += peq;
        if (!pa)
            return std::nullopt;
        p.peqAuditor = *pa;
    }
    auto la = cmpt::LinkageProof::deserialize(sub(off, link));
    off += link;
    auto lb = cmpt::LinkageProof::deserialize(sub(off, link));
    off += link;
    if (!la || !lb)
        return std::nullopt;
    p.linkAmount = *la;
    p.linkBalance = *lb;

    // The two range proofs are self-describing: byte 0 is the bit width.
    std::size_t const rem = in.size() - off;
    std::uint8_t const bitsA = in.data()[off];
    if (bitsA == 0 || bitsA > cmpt::RangeProof::kMaxBits)
        return std::nullopt;
    std::size_t const lenA = cmpt::RangeProof::serializedSize(bitsA);
    if (rem <= lenA)
        return std::nullopt;
    auto ra = cmpt::RangeProof::deserialize(sub(off, lenA));
    auto rb = cmpt::RangeProof::deserialize(sub(off + lenA, rem - lenA));
    if (!ra || !rb)
        return std::nullopt;
    p.rangeAmount = *ra;
    p.rangeBalance = *rb;
    return p;
}

cmpt::ECPoint
loadPoint(SLE const& sle, SField const& f)
{
    auto const b = sle.getFieldVL(f);
    return cmpt::ECPoint::deserialize(Slice{b.data(), b.size()})
        .value_or(cmpt::ECPoint::infinity());
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
ConfidentialMPTSend::preflight(PreflightContext const& ctx)
{
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() == ctx.tx[sfAccount])
        return temMALFORMED;

    if (ctx.tx[sfAccount] == ctx.tx[sfDestination])
        return temMALFORMED;

    if (!validCiphertext(ctx.tx[~sfSenderEncryptedAmount]) ||
        !validCiphertext(ctx.tx[~sfDestinationEncryptedAmount]) ||
        !validCiphertext(ctx.tx[~sfIssuerEncryptedAmount]))
        return temMALFORMED;

    if (ctx.tx.isFieldPresent(sfAuditorEncryptedAmount) &&
        !validCiphertext(ctx.tx[~sfAuditorEncryptedAmount]))
        return temMALFORMED;

    if (!validPoint(ctx.tx[~sfAmountCommitment]) ||
        !validPoint(ctx.tx[~sfBalanceCommitment]))
        return temMALFORMED;

    if (auto const err = credentials::checkFields(ctx.tx, ctx.j); !isTesSuccess(err))
        return err;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::preclaim(PreclaimContext const& ctx)
{
    auto const id = ctx.tx[sfMPTokenIssuanceID];
    auto const sleIssuance = ctx.view.read(keylet::mptIssuance(id));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    // Confidential transfers are incompatible with a non-zero transfer fee.
    if (sleIssuance->isFieldPresent(sfTransferFee) &&
        sleIssuance->getFieldU16(sfTransferFee) != 0)
        return tecNO_PERMISSION;

    if (!sleIssuance->isFlag(lsfMPTCanConfidentialAmount))
        return tecNO_PERMISSION;
    if (!sleIssuance->isFlag(lsfMPTCanTransfer))
        return tecNO_AUTH;
    if (!sleIssuance->isFieldPresent(sfIssuerEncryptionKey))
        return tecNO_PERMISSION;

    auto const dest = ctx.tx[sfDestination];
    if (!ctx.view.exists(keylet::account(dest)))
        return tecNO_TARGET;

    auto const sleSender = ctx.view.read(keylet::mptoken(id, ctx.tx[sfAccount]));
    if (!sleSender || !sleSender->isFieldPresent(sfHolderEncryptionKey) ||
        !sleSender->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;

    auto const sleDest = ctx.view.read(keylet::mptoken(id, dest));
    if (!sleDest || !sleDest->isFieldPresent(sfHolderEncryptionKey) ||
        !sleDest->isFieldPresent(sfConfidentialBalanceInbox))
        return tecNO_PERMISSION;

    // The auditor ciphertext is mandatory when an auditor key is configured,
    // and forbidden otherwise: a non-audited issuance must not accept an
    // unverified auditor mirror.
    bool const hasAuditor = sleIssuance->isFieldPresent(sfAuditorEncryptionKey);
    if (hasAuditor != ctx.tx.isFieldPresent(sfAuditorEncryptedAmount))
        return tecNO_PERMISSION;

    MPTIssue const mptIssue{id};
    if (isFrozen(ctx.view, ctx.tx[sfAccount], mptIssue) ||
        isFrozen(ctx.view, dest, mptIssue))
        return tecFROZEN;

    if (sleIssuance->isFlag(lsfMPTRequireAuth) &&
        (!sleSender->isFlag(lsfMPTAuthorized) || !sleDest->isFlag(lsfMPTAuthorized)))
        return tecNO_AUTH;

    if (auto const err = credentials::valid(ctx.tx, ctx.view, ctx.tx[sfAccount], ctx.j);
        !isTesSuccess(err))
        return err;

    // --- Zero-knowledge verification ---
    auto const senderKey = loadPoint(*sleSender, sfHolderEncryptionKey);
    auto const destKey = loadPoint(*sleDest, sfHolderEncryptionKey);
    auto const issuerKey = loadPoint(*sleIssuance, sfIssuerEncryptionKey);
    if (senderKey.isInfinity() || destKey.isInfinity() || issuerKey.isInfinity())
        return tecBAD_PROOF;

    auto const senderCt =
        *cmpt::ElGamalCiphertext::deserialize(ctx.tx[sfSenderEncryptedAmount]);
    auto const destCt =
        *cmpt::ElGamalCiphertext::deserialize(ctx.tx[sfDestinationEncryptedAmount]);
    auto const issuerCt =
        *cmpt::ElGamalCiphertext::deserialize(ctx.tx[sfIssuerEncryptedAmount]);
    auto const amountCommit =
        *cmpt::PedersenCommitment::deserialize(ctx.tx[sfAmountCommitment]);
    auto const balanceCommit =
        *cmpt::PedersenCommitment::deserialize(ctx.tx[sfBalanceCommitment]);

    auto const proofs = parseSendProofs(ctx.tx[sfZKProof], hasAuditor);
    if (!proofs)
        return tecBAD_PROOF;

    // Ciphertext consistency across the recipient / mirror ciphertexts.
    if (!proofs->peqDest.verify(senderKey, destKey, senderCt, destCt) ||
        !proofs->peqIssuer.verify(senderKey, issuerKey, senderCt, issuerCt))
        return tecBAD_PROOF;

    if (hasAuditor)
    {
        auto const auditorKey = loadPoint(*sleIssuance, sfAuditorEncryptionKey);
        auto const auditorCt =
            *cmpt::ElGamalCiphertext::deserialize(ctx.tx[sfAuditorEncryptedAmount]);
        if (auditorKey.isInfinity() || !proofs->peqAuditor ||
            !proofs->peqAuditor->verify(senderKey, auditorKey, senderCt, auditorCt))
            return tecBAD_PROOF;
    }

    // Amount linkage + range proof on the transferred amount.
    if (!proofs->linkAmount.verify(senderKey, senderCt, amountCommit) ||
        !proofs->rangeAmount.verify(amountCommit))
        return tecBAD_PROOF;

    // Balance linkage + range proof on the post-debit spending balance
    // (proves the remaining confidential balance is non-negative).
    auto const postDebit =
        loadCt(*sleSender, sfConfidentialBalanceSpending) - senderCt;
    if (!proofs->linkBalance.verify(senderKey, postDebit, balanceCommit) ||
        !proofs->rangeBalance.verify(balanceCommit))
        return tecBAD_PROOF;

    return tesSUCCESS;
}

TER
ConfidentialMPTSend::doApply()
{
    auto const id = ctx_.tx[sfMPTokenIssuanceID];
    auto const dest = ctx_.tx[sfDestination];
    auto const sleSender = view().peek(keylet::mptoken(id, accountID_));
    auto const sleDest = view().peek(keylet::mptoken(id, dest));
    if (!sleSender || !sleDest)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto const sleDestAccount = view().read(keylet::account(dest));
    if (auto err = verifyDepositPreauth(
            ctx_.tx, ctx_.view(), accountID_, dest, sleDestAccount, ctx_.journal);
        !isTesSuccess(err))
        return err;

    // Mirror the auditor ciphertext only when the issuance actually has an
    // auditor key, not merely when the tx field is present.
    auto const sleIssuance = view().read(keylet::mptIssuance(id));
    bool const hasAuditor = sleIssuance &&
        sleIssuance->isFieldPresent(sfAuditorEncryptionKey) &&
        ctx_.tx.isFieldPresent(sfAuditorEncryptedAmount);
    auto txCt = [&](auto const& f) {
        return *cmpt::ElGamalCiphertext::deserialize(ctx_.tx[f]);
    };
    auto write =
        [&](SLE::pointer const& sle, SField const& f, cmpt::ElGamalCiphertext const& ct) {
            auto const s = ct.serialize();
            sle->setFieldVL(f, Slice{s.data(), s.size()});
        };

    auto const senderCt = txCt(sfSenderEncryptedAmount);
    auto const destCt = txCt(sfDestinationEncryptedAmount);
    auto const issuerCt = txCt(sfIssuerEncryptedAmount);

    // Sender: homomorphically debit the spending balance and bump the version.
    write(
        sleSender,
        sfConfidentialBalanceSpending,
        loadCt(*sleSender, sfConfidentialBalanceSpending) - senderCt);
    std::uint32_t const v = sleSender->isFieldPresent(sfConfidentialBalanceVersion)
        ? sleSender->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    sleSender->setFieldU32(
        sfConfidentialBalanceVersion, v == 0xFFFFFFFFu ? 0u : v + 1u);

    // Receiver: homomorphically credit the inbox.
    write(
        sleDest,
        sfConfidentialBalanceInbox,
        loadCt(*sleDest, sfConfidentialBalanceInbox) + destCt);

    // Issuer mirrors move with the funds.
    write(
        sleSender,
        sfIssuerEncryptedBalance,
        loadCt(*sleSender, sfIssuerEncryptedBalance) - issuerCt);
    write(
        sleDest,
        sfIssuerEncryptedBalance,
        loadCt(*sleDest, sfIssuerEncryptedBalance) + issuerCt);

    if (hasAuditor)
    {
        auto const auditorCt = txCt(sfAuditorEncryptedAmount);
        write(
            sleSender,
            sfAuditorEncryptedBalance,
            loadCt(*sleSender, sfAuditorEncryptedBalance) - auditorCt);
        write(
            sleDest,
            sfAuditorEncryptedBalance,
            loadCt(*sleDest, sfAuditorEncryptedBalance) + auditorCt);
    }

    view().update(sleSender);
    view().update(sleDest);
    return tesSUCCESS;
}

void
ConfidentialMPTSend::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
}

bool
ConfidentialMPTSend::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
