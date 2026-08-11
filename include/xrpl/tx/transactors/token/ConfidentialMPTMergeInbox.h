#pragma once

#include <xrpl/tx/Transactor.h>

namespace xrpl {

/** Merge a holder's confidential inbox balance into their spending balance
    (XLS-0096).

    Homomorphically adds sfConfidentialBalanceInbox into
    sfConfidentialBalanceSpending, resets the inbox to a canonical encrypted
    zero, and increments sfConfidentialBalanceVersion (wrapping at the maximum
    32-bit value). This is a proof-free operation: no ZKP is required.
*/
class ConfidentialMPTMergeInbox : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit ConfidentialMPTMergeInbox(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    // 10x base fee for ZK-proof verification cost (XLS-0096 §14).
    static XRPAmount
    calculateBaseFee(ReadView const& view, STTx const& tx);

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
