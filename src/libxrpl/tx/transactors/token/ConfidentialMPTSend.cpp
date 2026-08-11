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
#include <vector>

namespace xrpl {

XRPAmount
ConfidentialMPTSend::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return cmpt::kConfidentialFeeMultiplier *
        Transactor::calculateBaseFee(view, tx);
}

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

// The transferred amount and the post-debit spending balance must both lie in
// [0, 2^63). The aggregated range proof is not self-describing, so the wire
// format pins the width and value count here: a bundle proving a wider (e.g.
// 64-bit) range would otherwise verify while asserting a weaker bound than this
// preclaim relies on.
constexpr std::uint8_t kSendRangeBits = 63;

// Two aggregated values: the transferred amount and the remaining spending
// balance, proven together in a single Bulletproof.
constexpr std::uint8_t kSendRangeValues = 2;

// Layout of the ZKProof bundle carried by ConfidentialMPTSend: a single
// 192-byte compact AND-composed sigma proof (CompactStandardProof) binding
// every recipient mirror under one shared ciphertext nonce, followed by one
// aggregated Bulletproof range proof (754 bytes) covering both the transferred
// amount and the remaining spending balance. The bundle is a fixed 946 bytes.
struct SendProofs
{
    cmpt::CompactStandardProof standard;
    cmpt::RangeProof range;  // aggregated over {amount, balance}
};

// Exact ZKProof bundle size: 192-byte compact sigma proof + 754-byte aggregated
// range proof = 946 bytes.
std::size_t
sendZKProofSize()
{
    return cmpt::CompactStandardProof::serializedSize() +
        cmpt::RangeProof::serializedSizeAggregated(
            kSendRangeBits, kSendRangeValues);
}

std::optional<SendProofs>
parseSendProofs(Slice const& in)
{
    constexpr std::size_t std_ = cmpt::CompactStandardProof::serializedSize();
    std::size_t const rng_ = cmpt::RangeProof::serializedSizeAggregated(
        kSendRangeBits, kSendRangeValues);
    if (in.size() != std_ + rng_)
        return std::nullopt;

    SendProofs p;
    auto sp = cmpt::CompactStandardProof::deserialize(Slice{in.data(), std_});
    if (!sp)
        return std::nullopt;
    p.standard = *sp;

    // The aggregated range proof carries no width byte: its shape (bit width
    // and value count) is fixed by the transaction type.
    auto rg = cmpt::RangeProof::deserializeAggregated(
        Slice{in.data() + std_, rng_}, kSendRangeBits, kSendRangeValues);
    if (!rg)
        return std::nullopt;
    p.range = *rg;
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

    // The ZKProof bundle is a fixed 946 bytes: a 192-byte compact sigma proof
    // followed by a 754-byte aggregated Bulletproof range proof. Reject any
    // other size up front so malformed bundles never reach proof verification.
    auto const zk = ctx.tx[~sfZKProof];
    if (!zk || zk->size() != sendZKProofSize())
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

    auto const proofs = parseSendProofs(ctx.tx[sfZKProof]);
    if (!proofs)
        return tecBAD_PROOF;

    // Bind the proof bundle to this transaction's context_id. The version is
    // the sender's pre-transaction confidential balance version (bumped in
    // doApply); getSeqValue() binds ticketed transactions to their ticket
    // number rather than sfSequence == 0.
    std::uint32_t const version =
        sleSender->isFieldPresent(sfConfidentialBalanceVersion)
        ? sleSender->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    auto const contextId = cmpt::sendContextId(
        ctx.tx[sfAccount], id, ctx.tx.getSeqValue(), dest, version);
    Slice const ctxId{contextId.data(), contextId.size()};

    // Assemble the recipient mirrors [sender, dest, issuer, (auditor)]. The
    // compact proof binds them under a single shared ciphertext nonce C1 and
    // rejects mismatched nonces, so every mirror must share senderCt.c1().
    std::vector<cmpt::ElGamalPublicKey> recipientKeys{
        senderKey, destKey, issuerKey};
    std::vector<cmpt::ElGamalCiphertext> recipientCts{
        senderCt, destCt, issuerCt};
    if (hasAuditor)
    {
        auto const auditorKey = loadPoint(*sleIssuance, sfAuditorEncryptionKey);
        auto const auditorCt = *cmpt::ElGamalCiphertext::deserialize(
            ctx.tx[sfAuditorEncryptedAmount]);
        if (auditorKey.isInfinity())
            return tecBAD_PROOF;
        recipientKeys.push_back(auditorKey);
        recipientCts.push_back(auditorCt);
    }

    // Post-debit spending balance: its range proof bounds the remaining
    // confidential balance to [0, 2^63), and the compact proof binds its
    // ownership to the sender's key.
    auto const postDebit =
        loadCt(*sleSender, sfConfidentialBalanceSpending) - senderCt;

    // Single compact AND-composed sigma proof: ciphertext equality across every
    // mirror, amount-commitment linkage, and post-debit balance ownership.
    if (!proofs->standard.verify(
            recipientKeys,
            recipientCts,
            amountCommit,
            senderKey,
            postDebit,
            balanceCommit,
            ctxId))
        return tecBAD_PROOF;

    // Aggregated range proof: the transferred amount and the remaining spending
    // balance both lie in [0, 2^63), proven together in a single Bulletproof.
    // The commitment order must match the prover: {amount, balance}.
    if (!proofs->range.verifyAggregated({amountCommit, balanceCommit}, ctxId))
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
