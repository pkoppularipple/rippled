#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/ECMath.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace xrpl {
namespace cmpt {

/** Higher-level cryptographic schemes for XLS-0096 Confidential MPT.

    Built on the EC primitives in ECMath.h:
      - Pedersen commitments (additively homomorphic, perfectly hiding).
      - Exponential EC-ElGamal encryption (additively homomorphic).
      - Schnorr proof of knowledge of an encryption secret key.
      - A bit-decomposition zero-knowledge range proof.

    Wire-format note: this slice fixes the in-memory algebra and a natural
    serialization (33-byte compressed points, 32-byte big-endian scalars). Exact
    byte-for-byte compatibility with the reference mpt-crypto library and the
    final Bulletproofs range-proof encoding is reconciled in the send-path
    slice; the range proof here is a self-contained, verifiable placeholder.
*/

/// Serialized size of an EC-ElGamal public key (one compressed point).
inline constexpr std::size_t kEncryptionKeySize = kPointSize;

/// Serialized size of an EC-ElGamal ciphertext (two compressed points).
inline constexpr std::size_t kCiphertextSize = 2 * kPointSize;

//------------------------------------------------------------------------------

/** A Pedersen commitment C = value*G + blind*H.

    Perfectly hiding and computationally binding. Commitments add
    homomorphically: commit(v1, r1) + commit(v2, r2) == commit(v1+v2, r1+r2).
*/
class PedersenCommitment
{
public:
    PedersenCommitment() = default;
    explicit PedersenCommitment(ECPoint c) : c_(c)
    {
    }

    static PedersenCommitment
    commit(std::uint64_t value, Scalar const& blind);

    static PedersenCommitment
    commit(Scalar const& value, Scalar const& blind);

    [[nodiscard]] PedersenCommitment
    operator+(PedersenCommitment const& o) const;

    [[nodiscard]] ECPoint const&
    point() const
    {
        return c_;
    }

    [[nodiscard]] bool
    operator==(PedersenCommitment const& o) const;

    [[nodiscard]] std::array<std::uint8_t, kPointSize>
    serialize() const;

    static std::optional<PedersenCommitment>
    deserialize(Slice const& in);

private:
    ECPoint c_;
};

//------------------------------------------------------------------------------

/// EC-ElGamal public key Y = secret*G.
using ElGamalPublicKey = ECPoint;

/// EC-ElGamal secret key.
struct ElGamalSecretKey
{
    Scalar x;

    static ElGamalSecretKey
    random();

    [[nodiscard]] ElGamalPublicKey
    publicKey() const;
};

/** Exponential EC-ElGamal ciphertext (c1, c2) = (k*G, m*G + k*Y).

    The message m is encoded in the exponent, which makes the scheme additively
    homomorphic: add() yields an encryption of the sum of the plaintexts.
    Recovering m requires solving a small discrete log, so decrypt() is bounded.
*/
class ElGamalCiphertext
{
public:
    ElGamalCiphertext() = default;
    ElGamalCiphertext(ECPoint c1, ECPoint c2) : c1_(c1), c2_(c2)
    {
    }

    static ElGamalCiphertext
    encrypt(ElGamalPublicKey const& pub, std::uint64_t m, Scalar const& k);

    static ElGamalCiphertext
    encrypt(ElGamalPublicKey const& pub, std::uint64_t m);

    /// Deterministic encryption of zero (canonical zero balance).
    static ElGamalCiphertext
    encryptZero();

    [[nodiscard]] ElGamalCiphertext
    operator+(ElGamalCiphertext const& o) const;

    /// Recover m*G = c2 - x*c1.
    [[nodiscard]] ECPoint
    decryptToPoint(Scalar const& secret) const;

    /// Recover m in [0, maxValue] via baby-step/giant-step; nullopt if absent.
    [[nodiscard]] std::optional<std::uint64_t>
    decrypt(Scalar const& secret, std::uint64_t maxValue) const;

    [[nodiscard]] ECPoint const&
    c1() const
    {
        return c1_;
    }
    [[nodiscard]] ECPoint const&
    c2() const
    {
        return c2_;
    }

    [[nodiscard]] bool
    operator==(ElGamalCiphertext const& o) const;

    [[nodiscard]] std::array<std::uint8_t, kCiphertextSize>
    serialize() const;

    static std::optional<ElGamalCiphertext>
    deserialize(Slice const& in);

private:
    ECPoint c1_;
    ECPoint c2_;
};

//------------------------------------------------------------------------------

/** Schnorr proof of knowledge of the secret key x for a public key Y = x*G.

    Used at registration to prove ownership of an encryption key and prevent
    rogue-key attacks. Non-interactive via Fiat-Shamir.
*/
class SchnorrProof
{
public:
    /// Serialized size: challenge scalar + response scalar.
    static constexpr std::size_t kSize = 2 * kScalarSize;

    SchnorrProof() = default;
    SchnorrProof(Scalar e, Scalar s) : e_(e), s_(s)
    {
    }

    static SchnorrProof
    prove(Scalar const& secret, ElGamalPublicKey const& pub);

    [[nodiscard]] bool
    verify(ElGamalPublicKey const& pub) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<SchnorrProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar s_;
};

//------------------------------------------------------------------------------

/** Zero-knowledge proof that a Pedersen commitment opens to a value in
    [0, 2^bits).

    Implemented by committing to each bit and proving, with a Schnorr OR proof,
    that every bit commitment opens to 0 or 1; the verifier additionally checks
    that the weighted sum of the bit commitments equals the input commitment.

    This is a correct, self-contained range proof. It is deliberately the simple
    (linear-size) construction; the succinct, aggregated Bulletproofs encoding
    is deferred to a later slice. Proof size is O(bits).
*/
class RangeProof
{
public:
    /// Maximum supported bit width.
    static constexpr std::uint8_t kMaxBits = 64;

    RangeProof() = default;

    /** Prove that commit(value, blind) lies in [0, 2^bits).

        @return the proof together with the commitment it proves.
    */
    static std::pair<RangeProof, PedersenCommitment>
    prove(std::uint64_t value, Scalar const& blind, std::uint8_t bits);

    [[nodiscard]] bool
    verify(PedersenCommitment const& commitment) const;

    [[nodiscard]] std::uint8_t
    bits() const
    {
        return bits_;
    }

    [[nodiscard]] std::vector<std::uint8_t>
    serialize() const;

    static std::optional<RangeProof>
    deserialize(Slice const& in);

private:
    // One Schnorr OR proof per bit, proving the bit commitment opens to 0 or 1.
    struct BitProof
    {
        ECPoint commitment;  // C_i = b_i*G + r_i*H
        Scalar c0;           // challenge for the "bit == 0" branch
        Scalar c1;           // challenge for the "bit == 1" branch
        Scalar z0;           // response for the "bit == 0" branch
        Scalar z1;           // response for the "bit == 1" branch
    };

    std::uint8_t bits_{0};
    std::vector<BitProof> bitProofs_;
};

}  // namespace cmpt
}  // namespace xrpl
