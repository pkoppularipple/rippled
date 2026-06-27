/**
 * Bidirectional cross-verification tests for XLS-0096 compact-sigma proofs.
 *
 * Tests rippled ↔ mpt-crypto reference library interoperability for:
 *   - CompactClawbackProof (64 B)
 *   - CompactConvertBackProof (128 B compact + 688 B range = 816 B total)
 *
 * CRITICAL: This file does NOT fake cross-verification. If a direction cannot
 * be wired due to missing C API surface, the test documents the limitation
 * and tests only the directions that ARE possible.
 */

#include <test/jtx.h>

#include <xrpl/basics/Slice.h>
#include <xrpl/basics/StringUtilities.h>
#include <xrpl/basics/strHex.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>

// Link against vendored mpt-crypto
#include <secp256k1_mpt.h>
#include <utility/mpt_utility.h>
#include <secp256k1.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

namespace xrpl::test {

class ConfidentialMPTCrossVerify_test : public beast::unit_test::Suite
{
    // Convert rippled ECPoint to secp256k1_pubkey
    static secp256k1_pubkey
    toSecp(secp256k1_context const* ctx, cmpt::ECPoint const& pt)
    {
        auto const ser = pt.serialize();
        secp256k1_pubkey pk;
        if (!secp256k1_ec_pubkey_parse(ctx, &pk, ser.data(), ser.size()))
            throw std::runtime_error("toSecp: invalid point");
        return pk;
    }

    // Convert rippled Scalar to 32-byte array
    static std::array<unsigned char, 32>
    scalarBytes(cmpt::Scalar const& s)
    {
        auto const b = s.bytes();
        std::array<unsigned char, 32> out;
        std::memcpy(out.data(), b.data(), 32);
        return out;
    }

    void
    testClawbackBidirectional()
    {
        testcase("Clawback: bidirectional rippled ↔ mpt-crypto");

        secp256k1_context* ctx = mpt_secp256k1_context();
        BEAST_EXPECT(ctx != nullptr);

        // Generate issuer keypair
        cmpt::Scalar const issuerSk = cmpt::Scalar::random();
        cmpt::ECPoint const issuerPub = cmpt::ECPoint::mulBase(issuerSk);
        std::uint64_t const amount = 12345;

        // Encrypt amount under issuer's key (mirror ciphertext)
        cmpt::Scalar const k = cmpt::Scalar::random();
        cmpt::ElGamalCiphertext const issuerMirror =
            cmpt::ElGamalCiphertext::encrypt(issuerPub, amount, k);

        // 32-byte dummy context ID (mpt-crypto API requires 32-byte hash)
        unsigned char context_id[32] = {0};

        // ----------------------------------------------------------
        // Direction (a): rippled prove → mpt-crypto verify
        // ----------------------------------------------------------
        {
            auto const proof =
                cmpt::CompactClawbackProof::prove(issuerSk, amount, issuerPub, issuerMirror);
            auto const proofBytes = proof.serialize();
            BEAST_EXPECT(proofBytes.size() == 64);

            secp256k1_pubkey P_iss = toSecp(ctx, issuerPub);
            secp256k1_pubkey C1 = toSecp(ctx, issuerMirror.c1());
            secp256k1_pubkey C2 = toSecp(ctx, issuerMirror.c2());

            int ok = secp256k1_compact_clawback_verify(
                ctx, proofBytes.data(), amount, &P_iss, &C1, &C2, context_id);
            BEAST_EXPECT(ok == 1);
        }

        // ----------------------------------------------------------
        // Direction (b): mpt-crypto prove → rippled verify
        // ----------------------------------------------------------
        {
            auto const sk_bytes = scalarBytes(issuerSk);
            secp256k1_pubkey P_iss = toSecp(ctx, issuerPub);
            secp256k1_pubkey C1 = toSecp(ctx, issuerMirror.c1());
            secp256k1_pubkey C2 = toSecp(ctx, issuerMirror.c2());

            unsigned char proof_out[SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE];
            int ok = secp256k1_compact_clawback_prove(
                ctx, proof_out, amount, sk_bytes.data(), &P_iss, &C1, &C2, context_id);
            BEAST_EXPECT(ok == 1);

            // Deserialize and verify via rippled
            auto const proofOpt = cmpt::CompactClawbackProof::deserialize(
                Slice{proof_out, sizeof(proof_out)});
            BEAST_EXPECT(proofOpt.has_value());
            BEAST_EXPECT(proofOpt->verify(amount, issuerPub, issuerMirror));
        }

        // ----------------------------------------------------------
        // Byte-identical serialization check
        // ----------------------------------------------------------
        {
            // rippled proof
            auto const proof1 =
                cmpt::CompactClawbackProof::prove(issuerSk, amount, issuerPub, issuerMirror);
            auto const bytes1 = proof1.serialize();

            // mpt-crypto proof
            auto const sk_bytes = scalarBytes(issuerSk);
            secp256k1_pubkey P_iss = toSecp(ctx, issuerPub);
            secp256k1_pubkey C1 = toSecp(ctx, issuerMirror.c1());
            secp256k1_pubkey C2 = toSecp(ctx, issuerMirror.c2());
            unsigned char bytes2[64];
            secp256k1_compact_clawback_prove(
                ctx, bytes2, amount, sk_bytes.data(), &P_iss, &C1, &C2, context_id);

            // Both should produce 64-byte proofs with IDENTICAL serialization
            // (deterministic nonce from witness + domain tag)
            BEAST_EXPECT(bytes1.size() == 64);
            BEAST_EXPECT(std::memcmp(bytes1.data(), bytes2, 64) == 0);
        }
    }

    void
    testConvertBackBidirectional()
    {
        testcase("ConvertBack: bidirectional rippled ↔ mpt-crypto (compact sigma only)");

        // NOTE: The mpt-crypto C API does NOT expose range-proof prove/verify separately.
        // ConvertBack's full bundle is 816 B (128 compact + 688 range). This test
        // cross-verifies the 128 B compact sigma proof ONLY. The RangeProof (688 B)
        // is tested for round-trip + exact size within rippled but NOT cross-verified
        // against mpt-crypto because the C API does not expose the standalone aggregated
        // Bulletproof prove/verify entrypoints for 63-bit proofs.

        secp256k1_context* ctx = mpt_secp256k1_context();
        BEAST_EXPECT(ctx != nullptr);

        // Generate holder keypair
        cmpt::Scalar const holderSk = cmpt::Scalar::random();
        cmpt::ECPoint const holderPub = cmpt::ECPoint::mulBase(holderSk);
        std::uint64_t const balance = 50000;
        cmpt::Scalar const rho = cmpt::Scalar::random();

        // Post-debit balance ciphertext
        cmpt::Scalar const r_balance = cmpt::Scalar::random();
        cmpt::ElGamalCiphertext const postDebit =
            cmpt::ElGamalCiphertext::encrypt(holderPub, balance, r_balance);

        // Balance commitment
        cmpt::PedersenCommitment const balanceCommit =
            cmpt::PedersenCommitment::commit(balance, rho);

        unsigned char context_id[32] = {0};

        // ----------------------------------------------------------
        // Direction (a): rippled prove → mpt-crypto verify
        // ----------------------------------------------------------
        {
            auto const proof = cmpt::CompactConvertBackProof::prove(
                holderSk, balance, rho, holderPub, postDebit, balanceCommit);
            auto const proofBytes = proof.serialize();
            BEAST_EXPECT(proofBytes.size() == 128);

            secp256k1_pubkey pk_A = toSecp(ctx, holderPub);
            secp256k1_pubkey B1 = toSecp(ctx, postDebit.c1());
            secp256k1_pubkey B2 = toSecp(ctx, postDebit.c2());
            secp256k1_pubkey PC_b = toSecp(ctx, balanceCommit.point());

            int ok = secp256k1_compact_convertback_verify(
                ctx, proofBytes.data(), &pk_A, &B1, &B2, &PC_b, context_id);
            BEAST_EXPECT(ok == 1);
        }

        // ----------------------------------------------------------
        // Direction (b): mpt-crypto prove → rippled verify
        // ----------------------------------------------------------
        {
            auto const sk_bytes = scalarBytes(holderSk);
            auto const rho_bytes = scalarBytes(rho);
            secp256k1_pubkey pk_A = toSecp(ctx, holderPub);
            secp256k1_pubkey B1 = toSecp(ctx, postDebit.c1());
            secp256k1_pubkey B2 = toSecp(ctx, postDebit.c2());
            secp256k1_pubkey PC_b = toSecp(ctx, balanceCommit.point());

            unsigned char proof_out[SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE];
            int ok = secp256k1_compact_convertback_prove(
                ctx,
                proof_out,
                balance,
                sk_bytes.data(),
                rho_bytes.data(),
                &pk_A,
                &B1,
                &B2,
                &PC_b,
                context_id);
            BEAST_EXPECT(ok == 1);

            // Deserialize and verify via rippled
            auto const proofOpt = cmpt::CompactConvertBackProof::deserialize(
                Slice{proof_out, sizeof(proof_out)});
            BEAST_EXPECT(proofOpt.has_value());
            BEAST_EXPECT(proofOpt->verify(holderPub, postDebit, balanceCommit));
        }

        // ----------------------------------------------------------
        // Byte-identical serialization check
        // ----------------------------------------------------------
        {
            auto const proof1 = cmpt::CompactConvertBackProof::prove(
                holderSk, balance, rho, holderPub, postDebit, balanceCommit);
            auto const bytes1 = proof1.serialize();

            auto const sk_bytes = scalarBytes(holderSk);
            auto const rho_bytes = scalarBytes(rho);
            secp256k1_pubkey pk_A = toSecp(ctx, holderPub);
            secp256k1_pubkey B1 = toSecp(ctx, postDebit.c1());
            secp256k1_pubkey B2 = toSecp(ctx, postDebit.c2());
            secp256k1_pubkey PC_b = toSecp(ctx, balanceCommit.point());
            unsigned char bytes2[128];
            secp256k1_compact_convertback_prove(
                ctx, bytes2, balance, sk_bytes.data(), rho_bytes.data(),
                &pk_A, &B1, &B2, &PC_b, context_id);

            BEAST_EXPECT(bytes1.size() == 128);
            BEAST_EXPECT(std::memcmp(bytes1.data(), bytes2, 128) == 0);
        }
    }

public:
    void
    run() override
    {
        testClawbackBidirectional();
        testConvertBackBidirectional();
    }
};

BEAST_DEFINE_TESTSUITE(ConfidentialMPTCrossVerify, app, xrpl);

}  // namespace xrpl::test