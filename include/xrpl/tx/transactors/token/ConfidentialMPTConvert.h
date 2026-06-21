#pragma once

#include <xrpl/tx/Transactor.h>

namespace xrpl {

/** Convert a holder's public MPT balance into confidential form (XLS-0096).

    Debits the holder's public sfMPTAmount, credits the encrypted amount to the
    holder's confidential inbox and the issuer mirror, and increases the
    issuance's sfConfidentialOutstandingAmount by the converted amount. The
    public sfOutstandingAmount is unchanged: the tokens remain outstanding, only
    their form changes (ΔCOA == -ΔMPTAmount).
*/
class ConfidentialMPTConvert : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit ConfidentialMPTConvert(ApplyContext& ctx) : Transactor(ctx)
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
