#pragma once

#include <xrpl/tx/Transactor.h>

namespace xrpl {

/** Confidential transfer of MPT value between two holders (XLS-0096).

    Homomorphically debits the sender's confidential spending balance and
    credits the receiver's confidential inbox, keeping the transferred amount
    hidden. Issuer (and optional auditor) mirrors are updated for both parties.
    Public balances, sfOutstandingAmount and sfConfidentialOutstandingAmount are
    all unchanged: the transfer is a redistribution of confidential supply.

    The transaction carries zero-knowledge proofs verified by validators:
      - plaintext-equality proofs binding the sender ciphertext to the
        destination / issuer / auditor ciphertexts (consistency),
      - a linkage proof binding sfAmountCommitment to the sender ciphertext, and
        a range proof on sfAmountCommitment (transfer amount in range),
      - a linkage proof binding sfBalanceCommitment to the post-debit spending
        balance, and a range proof on sfBalanceCommitment (remaining >= 0).
*/
class ConfidentialMPTSend : public Transactor
{
public:
    static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;

    explicit ConfidentialMPTSend(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    // 10x base fee for ZK-proof verification cost (XLS-0096 §14).
    static XRPAmount
    calculateBaseFee(ReadView const& view, STTx const& tx);

    static bool
    checkExtraFeatures(PreflightContext const& ctx);

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
