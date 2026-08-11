#pragma once

#include <xrpl/tx/Transactor.h>

namespace xrpl {

/** Issuer clawback of a holder's confidential MPT balance (XLS-0096).

    An issuer-only transaction that forcibly burns a holder's entire confidential
    balance, permanently removing those tokens from circulation. Both the public
    sfOutstandingAmount (OA) and the issuance's sfConfidentialOutstandingAmount
    (COA) are decreased by the revealed sfMPTAmount; nothing is credited to any
    account (ΔOA == ΣΔMPT + ΔCOA holds as -M == 0 + -M, which the existing
    ValidMPTPayment invariant already enforces).

    On success the holder's confidential ciphertexts (inbox, spending, issuer
    mirror, and — when the issuance is audited — the auditor mirror) are reset to
    the canonical encrypted zero and the spending-balance version is bumped.

    The revealed amount is proven correct against the holder's on-ledger
    sfIssuerEncryptedBalance (issuer mirror) by a 64-byte compact-sigma clawback
    proof, verified through knowledge of the issuer's secret key: it establishes
    P_iss == sk_iss*G and C2 - sfMPTAmount*G == sk_iss*C1, proving the mirror
    encrypts exactly sfMPTAmount. No range proof is needed — the entire balance
    is burned and the remainder is exactly encrypted zero.
*/
class ConfidentialMPTClawback : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit ConfidentialMPTClawback(ApplyContext& ctx) : Transactor(ctx)
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
