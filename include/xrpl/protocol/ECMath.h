#pragma once

#include <xrpl/basics/Slice.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace xrpl {
namespace cmpt {

/** Elliptic-curve math primitives for XLS-0096 Confidential MPT.

    These wrap libsecp256k1 to provide a small, self-contained algebra over the
    secp256k1 group: a prime-order scalar field (modulo the curve order n) and
    group elements (points), together with the two independent generators G and
    H used by Pedersen commitments and EC-ElGamal encryption.

    This layer is pure cryptographic math: it does not depend on, and is not
    gated by, any amendment. Ledger-facing code that consumes these primitives
    is responsible for feature gating.
*/

/// Size of a serialized scalar (32-byte big-endian, reduced mod n).
inline constexpr std::size_t kScalarSize = 32;

/// Size of a serialized group element (33-byte SEC1 compressed point).
inline constexpr std::size_t kPointSize = 33;

/** An element of the scalar field Z_n, where n is the secp256k1 curve order.

    Values are always stored reduced modulo n in big-endian byte order. All
    arithmetic is performed modulo n.
*/
class Scalar
{
public:
    /// Construct the additive identity (zero).
    Scalar();

    /// Construct from a 64-bit unsigned integer (always < n).
    explicit Scalar(std::uint64_t v);

    /// Construct from big-endian bytes, reducing modulo n.
    explicit Scalar(Slice const& be);

    /// Construct from a 32-byte big-endian array, reducing modulo n.
    explicit Scalar(std::array<std::uint8_t, kScalarSize> const& be);

    /// Return a uniformly random scalar in [0, n).
    static Scalar
    random();

    [[nodiscard]] bool
    isZero() const;

    [[nodiscard]] Scalar
    operator+(Scalar const& o) const;
    [[nodiscard]] Scalar
    operator-(Scalar const& o) const;
    [[nodiscard]] Scalar
    operator*(Scalar const& o) const;

    /// Additive inverse (n - x mod n).
    [[nodiscard]] Scalar
    negate() const;

    /// Multiplicative inverse modulo n; nullopt if this is zero.
    [[nodiscard]] std::optional<Scalar>
    invert() const;

    [[nodiscard]] bool
    operator==(Scalar const& o) const;
    [[nodiscard]] bool
    operator!=(Scalar const& o) const;

    [[nodiscard]] std::array<std::uint8_t, kScalarSize> const&
    bytes() const
    {
        return d_;
    }

    [[nodiscard]] Slice
    slice() const
    {
        return Slice{d_.data(), d_.size()};
    }

private:
    std::array<std::uint8_t, kScalarSize> d_{};
};

/** A point on the secp256k1 curve, including the point at infinity.

    libsecp256k1's public-key type cannot represent the identity element, so it
    is tracked explicitly. A serialized infinity is encoded as 33 zero bytes,
    which is never a valid compressed point.
*/
class ECPoint
{
public:
    /// Construct the point at infinity (group identity).
    ECPoint();

    static ECPoint
    infinity();

    /// The standard secp256k1 base point G.
    static ECPoint
    base();

    /// A second, independent "nothing-up-my-sleeve" generator H.
    static ECPoint
    generatorH();

    /// Compute s*G.
    static ECPoint
    mulBase(Scalar const& s);

    /// Compute s*P.
    static ECPoint
    mul(Scalar const& s, ECPoint const& p);

    /// Parse a 33-byte compressed point (or all-zero infinity); nullopt if bad.
    static std::optional<ECPoint>
    deserialize(Slice const& in);

    [[nodiscard]] bool
    isInfinity() const
    {
        return inf_;
    }

    [[nodiscard]] ECPoint
    operator+(ECPoint const& o) const;
    [[nodiscard]] ECPoint
    operator-(ECPoint const& o) const;
    [[nodiscard]] ECPoint
    negate() const;

    [[nodiscard]] bool
    operator==(ECPoint const& o) const;
    [[nodiscard]] bool
    operator!=(ECPoint const& o) const;

    /// 33-byte compressed encoding; infinity serializes to all zero bytes.
    [[nodiscard]] std::array<std::uint8_t, kPointSize>
    serialize() const;

private:
    bool inf_{true};
    std::array<std::uint8_t, kPointSize> d_{};
};

/// Domain-separated hash of arbitrary data to a scalar in [0, n).
Scalar
hashToScalar(Slice const& domain, std::vector<Slice> const& parts);

/// Domain-separated hash of data to a curve point (try-and-increment).
ECPoint
hashToPoint(Slice const& domain, Slice const& data);

}  // namespace cmpt
}  // namespace xrpl
