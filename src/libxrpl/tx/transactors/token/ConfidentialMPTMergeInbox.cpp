#include <xrpl/tx/transactors/token/ConfidentialMPTMergeInbox.h>

#include <xrpl/protocol/ConfidentialMPT.h>
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

namespace xrpl {

XRPAmount
ConfidentialMPTMergeInbox::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    return confidentialBaseFee(view, tx);
}

NotTEC
ConfidentialMPTMergeInbox::preflight(PreflightContext const& ctx)
{
    // The issuer account cannot hold confidential balances, so it cannot merge.
    if (MPTIssue{ctx.tx[sfMPTokenIssuanceID]}.getIssuer() == ctx.tx[sfAccount])
        return temMALFORMED;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::preclaim(PreclaimContext const& ctx)
{
    auto const sleIssuance =
        ctx.view.read(keylet::mptIssuance(ctx.tx[sfMPTokenIssuanceID]));
    if (!sleIssuance)
        return tecOBJECT_NOT_FOUND;

    if (!sleIssuance->isFlag(lsfMPTCanConfidentialAmount))
        return tecNO_PERMISSION;

    auto const sleToken =
        ctx.view.read(keylet::mptoken(ctx.tx[sfMPTokenIssuanceID], ctx.tx[sfAccount]));
    if (!sleToken)
        return tecOBJECT_NOT_FOUND;

    // The holder must have initialized confidential state.
    if (!sleToken->isFieldPresent(sfConfidentialBalanceInbox) ||
        !sleToken->isFieldPresent(sfConfidentialBalanceSpending))
        return tecNO_PERMISSION;

    // Authorization and lock constraints.
    if (sleIssuance->isFlag(lsfMPTRequireAuth) && !sleToken->isFlag(lsfMPTAuthorized))
        return tecNO_AUTH;

    // XLS-0096 §9.2.1.2 (items 5 & 6): an individual or issuance-level lock
    // rejects the merge with tecLOCKED.
    if (sleToken->isFlag(lsfMPTLocked) || sleIssuance->isFlag(lsfMPTLocked))
        return tecLOCKED;

    return tesSUCCESS;
}

TER
ConfidentialMPTMergeInbox::doApply()
{
    auto const sle =
        view().peek(keylet::mptoken(ctx_.tx[sfMPTokenIssuanceID], accountID_));
    if (!sle)
        return tecINTERNAL;  // LCOV_EXCL_LINE

    auto readCt = [&](SField const& f) -> cmpt::ElGamalCiphertext {
        if (sle->isFieldPresent(f))
        {
            auto const b = sle->getFieldVL(f);
            if (auto ct = cmpt::ElGamalCiphertext::deserialize(Slice{b.data(), b.size()}))
                return *ct;
        }
        return cmpt::ElGamalCiphertext::encryptZero();
    };
    auto writeCt = [&](SField const& f, cmpt::ElGamalCiphertext const& ct) {
        auto const s = ct.serialize();
        sle->setFieldVL(f, Slice{s.data(), s.size()});
    };

    // Spending += Inbox; Inbox reset to canonical encrypted zero.
    auto const spending = readCt(sfConfidentialBalanceSpending);
    auto const inbox = readCt(sfConfidentialBalanceInbox);
    writeCt(sfConfidentialBalanceSpending, spending + inbox);
    writeCt(sfConfidentialBalanceInbox, cmpt::ElGamalCiphertext::encryptZero());

    // Bump the spending-balance version, wrapping at the 32-bit maximum.
    std::uint32_t const v = sle->isFieldPresent(sfConfidentialBalanceVersion)
        ? sle->getFieldU32(sfConfidentialBalanceVersion)
        : 0u;
    sle->setFieldU32(
        sfConfidentialBalanceVersion, v == 0xFFFFFFFFu ? 0u : v + 1u);

    view().update(sle);
    return tesSUCCESS;
}

void
ConfidentialMPTMergeInbox::visitInvariantEntry(bool, SLE::const_ref, SLE::const_ref)
{
}

bool
ConfidentialMPTMergeInbox::finalizeInvariants(
    STTx const&,
    TER,
    XRPAmount,
    ReadView const&,
    beast::Journal const&)
{
    return true;
}

}  // namespace xrpl
