#pragma once

#include <xrpl/basics/Slice.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/ECMath.h>
#include <xrpl/protocol/UintTypes.h>

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
      - An aggregated Bulletproofs zero-knowledge range proof.

    Wire-format note: this slice fixes the in-memory algebra and a natural
    serialization (33-byte compressed points, 32-byte big-endian scalars). The
    range proof is a self-contained, sound Bulletproof (logarithmic proof size).

    The compact AND-composed sigma proofs (CompactClawbackProof,
    CompactConvertBackProof, CompactStandardProof) are transcript-reconciled
    with the reference mpt-crypto library: a SHA-256 Fiat-Shamir challenge over
    the same statement ordering, 33-byte compressed points, 32-byte big-endian
    scalars, and an optional 32-byte context_id. They cross-verify
    bidirectionally with mpt-crypto (each implementation verifies the other's
    proofs). Proofs are NOT bit-reproducible across implementations because the
    prover's nonce is independent randomness (mpt-crypto salts its
    deterministic-nonce HKDF with fresh entropy), but interoperability does not
    depend on a shared nonce. The aggregated Bulletproof range proof remains
    self-consistent only, as the reference C API exposes no standalone
    range-proof entrypoint. Send (tt88) uses CompactStandardProof: all recipient
    mirrors share a single ciphertext nonce r (shared-randomness model), which
    the succinct 192-byte proof binds together.
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

    /// Homomorphic subtraction: yields an encryption of the difference of the
    /// plaintexts (component-wise point subtraction).
    [[nodiscard]] ElGamalCiphertext
    operator-(ElGamalCiphertext const& o) const;

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
    rogue-key attacks. Non-interactive via Fiat-Shamir. The challenge is
    reduce32(SHA256("CMPT_POK_SK_REGISTER" || Y || T || context_id)), matching
    the reference mpt-crypto secp256k1_mpt_pok_sk_* byte-for-byte; an optional
    32-byte context_id binds the proof to a single transaction. The two
    implementations cross-verify bidirectionally but are NOT bit-reproducible
    because the prover's nonce is independent randomness.
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
    prove(
        Scalar const& secret,
        ElGamalPublicKey const& pub,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(ElGamalPublicKey const& pub, Slice const& contextId = {}) const;

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

    Aggregated Bulletproofs range proof (Bunz et al.). The value's bit vector is
    committed in A; a blinding polynomial in S; the inner-product relation that
    ties the bits to the committed value is then collapsed by a logarithmic
    inner-product argument (the L/R rounds below). Proof size is O(log bits)
    rather than O(bits): one byte of width, four points (A, S, T1, T2), three
    scalars (tauX, mu, tHat), then 2*ceil(log2(bits)) points and two scalars for
    the inner-product argument.

    Soundness fixes the value to lie in [0, 2^bits): the proof binds exactly
    `bits` bit positions, so the post-debit balance width (63) still detects
    underflow. All challenges come from the domain-separated Fiat-Shamir
    transcript built on hashToScalar; all generators are nothing-up-my-sleeve
    points from hashToPoint, so the scheme uses only the ECMath primitives.

    Wire layout (big-endian scalars, SEC1-compressed points):
        [0]                      bits (1 byte)
        A, S, T1, T2             4 * kPointSize
        tauX, mu, tHat           3 * kScalarSize
        L_0..L_{k-1}, R_0..R_{k-1}   2*k * kPointSize, k = rounds(bits)
        a, b                     2 * kScalarSize
*/
class RangeProof
{
public:
    /// Maximum supported bit width.
    static constexpr std::uint8_t kMaxBits = 64;

    RangeProof() = default;

    /** Prove that commit(value, blind) lies in [0, 2^bits).

        An optional 32-byte context_id is folded into the Fiat-Shamir
        transcript (before the first challenge, so it binds every subsequent
        challenge), binding the proof to a single transaction.

        @return the proof together with the commitment it proves.
    */
    static std::pair<RangeProof, PedersenCommitment>
    prove(
        std::uint64_t value,
        Scalar const& blind,
        std::uint8_t bits,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(PedersenCommitment const& commitment, Slice const& contextId = {})
        const;

    [[nodiscard]] std::uint8_t
    bits() const
    {
        return bits_;
    }

    /// Number of inner-product recursion rounds for a given bit width.
    static std::size_t
    rounds(std::uint8_t bits);

    /// Exact serialized byte length for a given bit width.
    static std::size_t
    serializedSize(std::uint8_t bits);

    [[nodiscard]] std::vector<std::uint8_t>
    serialize() const;

    static std::optional<RangeProof>
    deserialize(Slice const& in);

private:
    std::uint8_t bits_{0};
    ECPoint a_;   // A: vector commitment to the value's bits
    ECPoint s_;   // S: vector commitment to the blinding terms
    ECPoint t1_;  // T1: commitment to the linear coefficient of t(X)
    ECPoint t2_;  // T2: commitment to the quadratic coefficient of t(X)
    Scalar tauX_;
    Scalar mu_;
    Scalar tHat_;
    std::vector<ECPoint> ipL_;  // inner-product argument left commitments
    std::vector<ECPoint> ipR_;  // inner-product argument right commitments
    Scalar ipa_;                // folded inner-product scalar a
    Scalar ipb_;                // folded inner-product scalar b
};

//------------------------------------------------------------------------------

/** Zero-knowledge proof that an EC-ElGamal ciphertext and a Pedersen
    commitment encode the same value, proven through knowledge of the
    ciphertext's secret key.

    Given a ciphertext ct = (c1, c2) under public key Y = x*G and a commitment
    P = m*G + r*H, the prover demonstrates knowledge of (x, m, r) such that:
      - Y  = x*G                  (ownership of the encryption key)
      - c2 = m*G + x*c1           (ct decrypts under x to m*G)
      - P  = m*G + r*H            (P commits to the same m)

    This is the "balance/amount linkage" building block of the send path: the
    relevant ciphertexts (the transfer amount and the post-debit spending
    balance) are encrypted under the holder's own key, so the holder can prove
    the link via knowledge of their secret key. Non-interactive via Fiat-Shamir.
*/
class LinkageProof
{
public:
    /// Serialized size: challenge + three response scalars.
    static constexpr std::size_t kSize = 4 * kScalarSize;

    /// Exact serialized byte length (fixed; mirrors RangeProof::serializedSize).
    static constexpr std::size_t
    serializedSize()
    {
        return kSize;
    }

    LinkageProof() = default;
    LinkageProof(Scalar e, Scalar zx, Scalar zm, Scalar zr)
        : e_(e), zx_(zx), zm_(zm), zr_(zr)
    {
    }

    /** Prove ct (under public key pub = secret*G) and commitment encode value.

        @param secret      the ElGamal secret key x (pub == x*G).
        @param value       the common plaintext m.
        @param blind       the Pedersen blinding factor r.
        @param ct          the ElGamal ciphertext encrypting m under pub.
        @param commitment  the Pedersen commitment m*G + r*H.
    */
    static LinkageProof
    prove(
        Scalar const& secret,
        std::uint64_t value,
        Scalar const& blind,
        ElGamalCiphertext const& ct,
        PedersenCommitment const& commitment,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(
        ElGamalPublicKey const& pub,
        ElGamalCiphertext const& ct,
        PedersenCommitment const& commitment,
        Slice const& contextId = {}) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<LinkageProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar zx_;
    Scalar zm_;
    Scalar zr_;
};

//------------------------------------------------------------------------------

/** Zero-knowledge proof that two EC-ElGamal ciphertexts, possibly under
    different public keys, encrypt the same plaintext.

    Given ct1 = (a1, a2) under Y1 and ct2 = (b1, b2) under Y2, the prover
    demonstrates knowledge of (m, k1, k2) such that:
      - a1 = k1*G,  a2 = m*G + k1*Y1
      - b1 = k2*G,  b2 = m*G + k2*Y2

    This is the "ciphertext consistency" building block of the send path: it
    proves the amount credited to the receiver / issuer / auditor mirrors equals
    the amount debited from the sender. Non-interactive via Fiat-Shamir.
*/
class PlaintextEqualityProof
{
public:
    /// Serialized size: challenge + three response scalars.
    static constexpr std::size_t kSize = 4 * kScalarSize;

    /// Exact serialized byte length (fixed; mirrors RangeProof::serializedSize).
    static constexpr std::size_t
    serializedSize()
    {
        return kSize;
    }

    PlaintextEqualityProof() = default;
    PlaintextEqualityProof(Scalar e, Scalar zm, Scalar z1, Scalar z2)
        : e_(e), zm_(zm), z1_(z1), z2_(z2)
    {
    }

    /** Prove ct1 (under pub1) and ct2 (under pub2) encrypt the same value.

        @param pub1   public key of the first ciphertext.
        @param pub2   public key of the second ciphertext.
        @param value  the common plaintext m.
        @param k1     randomness used to form ct1.
        @param k2     randomness used to form ct2.
    */
    static PlaintextEqualityProof
    prove(
        ElGamalPublicKey const& pub1,
        ElGamalPublicKey const& pub2,
        std::uint64_t value,
        Scalar const& k1,
        Scalar const& k2,
        ElGamalCiphertext const& ct1,
        ElGamalCiphertext const& ct2,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(
        ElGamalPublicKey const& pub1,
        ElGamalPublicKey const& pub2,
        ElGamalCiphertext const& ct1,
        ElGamalCiphertext const& ct2,
        Slice const& contextId = {}) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<PlaintextEqualityProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar zm_;
    Scalar z1_;
    Scalar z2_;
};

//------------------------------------------------------------------------------

/** Compact AND-composed sigma proof for Clawback (XLS-0096, issue #13).

    Proves knowledge of issuer secret key sk_iss such that:
      - P_iss = sk_iss*G           (issuer public key)
      - C2 - m*G = sk_iss*C1       (issuer mirror ciphertext decrypts to amount m)

    Compact proof: (e, z_sk) in Z_q^2 = 64 bytes.
    Domain: "CMPT_CLAWBACK_SIGMA"
*/
class CompactClawbackProof
{
public:
    static constexpr std::size_t kSize = 64;

    static constexpr std::size_t
    serializedSize()
    {
        return kSize;
    }

    CompactClawbackProof() = default;
    CompactClawbackProof(Scalar e, Scalar zsk) : e_(e), zsk_(zsk)
    {
    }

    static CompactClawbackProof
    prove(
        Scalar const& secret,
        std::uint64_t amount,
        ElGamalPublicKey const& pub,
        ElGamalCiphertext const& issuerMirror,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(
        std::uint64_t amount,
        ElGamalPublicKey const& pub,
        ElGamalCiphertext const& issuerMirror,
        Slice const& contextId = {}) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<CompactClawbackProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar zsk_;
};

//------------------------------------------------------------------------------

/** Compact AND-composed sigma proof for ConvertBack (XLS-0096, issue #14 partial).

    Proves knowledge of (sk_A, b, rho) such that:
      - P_A = sk_A*G                 (holder public key)
      - B2 - b*G = sk_A*B1           (post-debit balance ciphertext decrypts to b)
      - PC_b = b*G + rho*H           (balance commitment)

    Compact proof: (e, z_b, z_rho, z_sk) in Z_q^4 = 128 bytes.
    Domain: "CMPT_CONVERTBACK_SIGMA"
*/
class CompactConvertBackProof
{
public:
    static constexpr std::size_t kSize = 128;

    static constexpr std::size_t
    serializedSize()
    {
        return kSize;
    }

    CompactConvertBackProof() = default;
    CompactConvertBackProof(Scalar e, Scalar zb, Scalar zrho, Scalar zsk)
        : e_(e), zb_(zb), zrho_(zrho), zsk_(zsk)
    {
    }

    static CompactConvertBackProof
    prove(
        Scalar const& secret,
        std::uint64_t balance,
        Scalar const& rho,
        ElGamalPublicKey const& pub,
        ElGamalCiphertext const& postDebit,
        PedersenCommitment const& balanceCommit,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(
        ElGamalPublicKey const& pub,
        ElGamalCiphertext const& postDebit,
        PedersenCommitment const& balanceCommit,
        Slice const& contextId = {}) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<CompactConvertBackProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar zb_;
    Scalar zrho_;
    Scalar zsk_;
};

//------------------------------------------------------------------------------

/** Compact AND-composed sigma proof for standard EC-ElGamal send (XLS-0096).

    Proves, under a single shared ciphertext nonce r, the combined send
    statement over n recipient mirrors (sender, destination, issuer, and
    optionally auditor) with witnesses (r, m, sk_A, rho, b):
      - C1            = r*G                          (shared ciphertext nonce)
      - C_{2,i}       = m*G + r*pk_i    for i = 1..n  (each mirror encrypts m)
      - PC_m          = m*G + r*H                     (amount commitment; blind == r)
      - pk_A          = sk_A*G                        (sender public key)
      - PC_b          = b*G + rho*H                   (post-debit balance commitment)
      - B2 - b*G      = sk_A*B1                       (balance ciphertext decrypts to b)

    Compact proof: (e, z_m, z_r, z_b, z_rho, z_sk) in Z_q^6 = 192 bytes. Domain:
    "CMPT_SEND_SIGMA". Transcript-reconciled with the reference mpt-crypto
    proof_compact_standard.c (SHA-256 Fiat-Shamir over the same statement and
    commitment ordering, 33-byte compressed points, 32-byte big-endian scalars,
    optional 32-byte context_id), so the two implementations cross-verify
    bidirectionally.

    All recipient ciphertexts MUST share the same first component C1: prove()
    throws and verify() returns false otherwise. The recipient key / ciphertext
    vectors are parallel (recipientKeys[i] owns recipientCts[i]) and must be
    non-empty.
*/
class CompactStandardProof
{
public:
    static constexpr std::size_t kSize = 192;

    static constexpr std::size_t
    serializedSize()
    {
        return kSize;
    }

    CompactStandardProof() = default;
    CompactStandardProof(
        Scalar e,
        Scalar zm,
        Scalar zr,
        Scalar zb,
        Scalar zrho,
        Scalar zsk)
        : e_(e), zm_(zm), zr_(zr), zb_(zb), zrho_(zrho), zsk_(zsk)
    {
    }

    /** Prove the shared-randomness send statement.

        @param secret        the sender's ElGamal secret key sk_A (pk_A = sk_A*G).
        @param amount        the transferred amount m.
        @param balance       the post-debit spending balance b.
        @param rShared       the shared ciphertext nonce r (also PC_m's blind).
        @param rho           the balance commitment blinding factor.
        @param recipientKeys the mirror public keys [sender, dest, issuer, ...].
        @param recipientCts  the mirror ciphertexts, all sharing C1 = r*G.
        @param amountCommit  the amount commitment PC_m = m*G + r*H.
        @param senderKey     the sender public key pk_A.
        @param postDebit     the post-debit spending balance ciphertext (B1, B2).
        @param balanceCommit the balance commitment PC_b = b*G + rho*H.
    */
    static CompactStandardProof
    prove(
        Scalar const& secret,
        std::uint64_t amount,
        std::uint64_t balance,
        Scalar const& rShared,
        Scalar const& rho,
        std::vector<ElGamalPublicKey> const& recipientKeys,
        std::vector<ElGamalCiphertext> const& recipientCts,
        PedersenCommitment const& amountCommit,
        ElGamalPublicKey const& senderKey,
        ElGamalCiphertext const& postDebit,
        PedersenCommitment const& balanceCommit,
        Slice const& contextId = {});

    [[nodiscard]] bool
    verify(
        std::vector<ElGamalPublicKey> const& recipientKeys,
        std::vector<ElGamalCiphertext> const& recipientCts,
        PedersenCommitment const& amountCommit,
        ElGamalPublicKey const& senderKey,
        ElGamalCiphertext const& postDebit,
        PedersenCommitment const& balanceCommit,
        Slice const& contextId = {}) const;

    [[nodiscard]] std::array<std::uint8_t, kSize>
    serialize() const;

    static std::optional<CompactStandardProof>
    deserialize(Slice const& in);

private:
    Scalar e_;
    Scalar zm_;
    Scalar zr_;
    Scalar zb_;
    Scalar zrho_;
    Scalar zsk_;
};

//------------------------------------------------------------------------------

/// Size of a transaction context_id (sha512_half output).
inline constexpr std::size_t kContextIdSize = 32;

/** Transaction context_id binding for XLS-0096 replay/domain separation.

    Each confidential spend or burn binds its compact sigma proof to a 32-byte
    context_id derived from the transaction's identity, so a proof captured on
    one transaction cannot be replayed on another. The derivation matches the
    reference mpt-crypto library byte-for-byte: sha512_half over a fixed 74-byte
    preimage built from the big-endian transaction type, account id, issuance
    id, sequence, and a per-type tail. Prover and verifier therefore agree
    across implementations.

    Pass the returned bytes as the `contextId` Slice to the matching
    CompactClawbackProof / CompactConvertBackProof prove() and verify() calls.
*/

/// Clawback context_id: binds the issuer account, issuance, transaction
/// sequence, and the targeted holder. Mirrors mpt_get_clawback_context_hash.
[[nodiscard]] std::array<std::uint8_t, kContextIdSize>
clawbackContextId(
    AccountID const& issuer,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    AccountID const& holder);

/// ConvertBack context_id: binds the spending account, issuance, transaction
/// sequence, and the pre-transaction confidential balance version. Mirrors
/// mpt_get_convert_back_context_hash.
[[nodiscard]] std::array<std::uint8_t, kContextIdSize>
convertBackContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    std::uint32_t version);

/// Convert (forward) context_id: binds the converting account and issuance to
/// the transaction sequence at encryption-key registration. Mirrors
/// mpt_get_convert_context_hash.
[[nodiscard]] std::array<std::uint8_t, kContextIdSize>
convertContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence);

/// Send context_id: binds the spending account, issuance, transaction
/// sequence, destination account, and the pre-transaction confidential balance
/// version. Mirrors mpt_get_send_context_hash.
[[nodiscard]] std::array<std::uint8_t, kContextIdSize>
sendContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    AccountID const& dest,
    std::uint32_t version);

}  // namespace cmpt
}  // namespace xrpl
