#pragma once

#include <xrpl/tx/Transactor.h>

namespace xrpl {

/** Convert a holder's confidential MPT balance back into public form (XLS-0096).

    Homomorphically debits the holder's confidential spending balance, credits
    the disclosed public amount to their sfMPTAmount, and decreases the
    issuance's sfConfidentialOutstandingAmount by the same amount. The public
    sfOutstandingAmount is unchanged: the tokens remain outstanding, only their
    form changes (ΔCOA == -ΔMPTAmount). Issuer (and optional auditor) mirrors are
    debited in lockstep, and the spending balance version is bumped.

    The withdrawn amount is public, so it is verified deterministically against
    the disclosed sfBlindingFactor exactly as ConfidentialMPTConvert does. The
    transaction additionally carries zero-knowledge proofs verified by
    validators, proving the post-debit spending balance is valid and
    non-negative:
      - a linkage proof binding sfBalanceCommitment to the post-debit spending
        balance through knowledge of the holder's secret key (balance ownership
        and key linkage), and
      - a range proof on sfBalanceCommitment (remaining balance >= 0).
*/
class ConfidentialMPTConvertBack : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit ConfidentialMPTConvertBack(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;

    void
    visitInvariantEntry(bool isDelete, SLE::const_ref before, SLE::const_ref after) override;

    [[nodiscard]] bool
    finalizeInvariants(
        STTx const& tx,
        TER result,
        XRPAmount fee,
        ReadView const& view,
        beast::Journal const& j) override;
};

}  // namespace xrpl
