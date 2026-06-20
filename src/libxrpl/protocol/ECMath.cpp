#include <xrpl/protocol/ECMath.h>

#include <xrpl/basics/contract.h>
#include <xrpl/beast/utility/rngfill.h>
#include <xrpl/crypto/csprng.h>
#include <xrpl/protocol/detail/secp256k1.h>
#include <xrpl/protocol/digest.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <secp256k1.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>

namespace xrpl {
namespace cmpt {

namespace {

using boost::multiprecision::cpp_int;

// The order n of the secp256k1 group.
cpp_int const&
order()
{
    static cpp_int const n(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return n;
}

cpp_int
beToInt(std::uint8_t const* p, std::size_t len)
{
    cpp_int r = 0;
    for (std::size_t i = 0; i < len; ++i)
        r = (r << 8) + p[i];
    return r;
}

// Reduce x into [0, n).
cpp_int
mod(cpp_int x)
{
    x %= order();
    if (x < 0)
        x += order();
    return x;
}

// Export a value in [0, n) to 32-byte big-endian.
std::array<std::uint8_t, kScalarSize>
intToBe(cpp_int x)
{
    std::array<std::uint8_t, kScalarSize> out{};
    for (std::size_t i = 0; i < kScalarSize; ++i)
    {
        out[kScalarSize - 1 - i] = static_cast<std::uint8_t>(x & 0xff);
        x >>= 8;
    }
    return out;
}

bool
parsePoint(
    std::array<std::uint8_t, kPointSize> const& d,
    secp256k1_pubkey& pk)
{
    return secp256k1_ec_pubkey_parse(
               secp256k1Context(), &pk, d.data(), d.size()) == 1;
}

std::array<std::uint8_t, kPointSize>
serializePoint(secp256k1_pubkey const& pk)
{
    std::array<std::uint8_t, kPointSize> out{};
    std::size_t len = out.size();
    secp256k1_ec_pubkey_serialize(
        secp256k1Context(), out.data(), &len, &pk, SECP256K1_EC_COMPRESSED);
    return out;
}

}  // namespace

//------------------------------------------------------------------------------
// Scalar
//------------------------------------------------------------------------------

Scalar::Scalar() = default;

Scalar::Scalar(std::uint64_t v)
{
    for (std::size_t i = 0; i < 8; ++i)
        d_[kScalarSize - 1 - i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
}

Scalar::Scalar(Slice const& be)
{
    d_ = intToBe(mod(beToInt(be.data(), be.size())));
}

Scalar::Scalar(std::array<std::uint8_t, kScalarSize> const& be)
{
    d_ = intToBe(mod(beToInt(be.data(), be.size())));
}

Scalar
Scalar::random()
{
    // 64 bytes of entropy reduced mod n makes the modular bias negligible.
    std::array<std::uint8_t, 64> buf{};
    beast::rngfill(buf.data(), buf.size(), cryptoPrng());
    Scalar s;
    s.d_ = intToBe(mod(beToInt(buf.data(), buf.size())));
    return s;
}

bool
Scalar::isZero() const
{
    return std::all_of(d_.begin(), d_.end(), [](std::uint8_t b) {
        return b == 0;
    });
}

Scalar
Scalar::operator+(Scalar const& o) const
{
    Scalar r;
    r.d_ = intToBe(
        mod(beToInt(d_.data(), kScalarSize) +
            beToInt(o.d_.data(), kScalarSize)));
    return r;
}

Scalar
Scalar::operator-(Scalar const& o) const
{
    Scalar r;
    r.d_ = intToBe(
        mod(beToInt(d_.data(), kScalarSize) -
            beToInt(o.d_.data(), kScalarSize)));
    return r;
}

Scalar
Scalar::operator*(Scalar const& o) const
{
    Scalar r;
    r.d_ = intToBe(
        mod(beToInt(d_.data(), kScalarSize) *
            beToInt(o.d_.data(), kScalarSize)));
    return r;
}

Scalar
Scalar::negate() const
{
    Scalar r;
    r.d_ = intToBe(mod(-beToInt(d_.data(), kScalarSize)));
    return r;
}

std::optional<Scalar>
Scalar::invert() const
{
    cpp_int const a = beToInt(d_.data(), kScalarSize);
    if (a == 0)
        return std::nullopt;
    Scalar r;
    r.d_ = intToBe(boost::multiprecision::powm(a, order() - 2, order()));
    return r;
}

bool
Scalar::operator==(Scalar const& o) const
{
    return d_ == o.d_;
}

bool
Scalar::operator!=(Scalar const& o) const
{
    return d_ != o.d_;
}

//------------------------------------------------------------------------------
// ECPoint
//------------------------------------------------------------------------------

ECPoint::ECPoint() = default;

ECPoint
ECPoint::infinity()
{
    return ECPoint{};
}

ECPoint
ECPoint::base()
{
    static ECPoint const g = mulBase(Scalar(std::uint64_t{1}));
    return g;
}

ECPoint
ECPoint::generatorH()
{
    static ECPoint const h = [] {
        auto const g = base().serialize();
        static constexpr char kDomain[] = "XLS96-MPT/H/v1";
        return hashToPoint(
            Slice{
                reinterpret_cast<std::uint8_t const*>(kDomain),
                sizeof(kDomain) - 1},
            Slice{g.data(), g.size()});
    }();
    return h;
}

ECPoint
ECPoint::mulBase(Scalar const& s)
{
    if (s.isZero())
        return infinity();
    secp256k1_pubkey pk;
    if (secp256k1_ec_pubkey_create(secp256k1Context(), &pk, s.bytes().data()) !=
        1)
        return infinity();
    ECPoint r;
    r.inf_ = false;
    r.d_ = serializePoint(pk);
    return r;
}

ECPoint
ECPoint::mul(Scalar const& s, ECPoint const& p)
{
    if (p.inf_ || s.isZero())
        return infinity();
    secp256k1_pubkey pk;
    if (!parsePoint(p.d_, pk))
        Throw<std::runtime_error>("ECPoint::mul: invalid point");
    if (secp256k1_ec_pubkey_tweak_mul(
            secp256k1Context(), &pk, s.bytes().data()) != 1)
        return infinity();
    ECPoint r;
    r.inf_ = false;
    r.d_ = serializePoint(pk);
    return r;
}

std::optional<ECPoint>
ECPoint::deserialize(Slice const& in)
{
    if (in.size() != kPointSize)
        return std::nullopt;
    if (std::all_of(in.data(), in.data() + in.size(), [](std::uint8_t b) {
            return b == 0;
        }))
        return infinity();
    std::array<std::uint8_t, kPointSize> d{};
    std::memcpy(d.data(), in.data(), kPointSize);
    secp256k1_pubkey pk;
    if (!parsePoint(d, pk))
        return std::nullopt;
    ECPoint r;
    r.inf_ = false;
    r.d_ = serializePoint(pk);
    return r;
}

ECPoint
ECPoint::operator+(ECPoint const& o) const
{
    if (inf_)
        return o;
    if (o.inf_)
        return *this;
    secp256k1_pubkey a, b;
    parsePoint(d_, a);
    parsePoint(o.d_, b);
    secp256k1_pubkey const* ins[2] = {&a, &b};
    secp256k1_pubkey out;
    if (secp256k1_ec_pubkey_combine(secp256k1Context(), &out, ins, 2) != 1)
        return infinity();  // result is the identity (a == -b)
    ECPoint r;
    r.inf_ = false;
    r.d_ = serializePoint(out);
    return r;
}

ECPoint
ECPoint::negate() const
{
    if (inf_)
        return infinity();
    secp256k1_pubkey pk;
    parsePoint(d_, pk);
    secp256k1_ec_pubkey_negate(secp256k1Context(), &pk);
    ECPoint r;
    r.inf_ = false;
    r.d_ = serializePoint(pk);
    return r;
}

ECPoint
ECPoint::operator-(ECPoint const& o) const
{
    return *this + o.negate();
}

bool
ECPoint::operator==(ECPoint const& o) const
{
    return inf_ == o.inf_ && (inf_ || d_ == o.d_);
}

bool
ECPoint::operator!=(ECPoint const& o) const
{
    return !(*this == o);
}

std::array<std::uint8_t, kPointSize>
ECPoint::serialize() const
{
    return d_;
}

//------------------------------------------------------------------------------
// Hash-to helpers
//------------------------------------------------------------------------------

Scalar
hashToScalar(Slice const& domain, std::vector<Slice> const& parts)
{
    OpensslSha512Hasher h;
    h(domain.data(), domain.size());
    for (auto const& p : parts)
        h(p.data(), p.size());
    auto const digest = OpensslSha512Hasher::result_type(h);
    return Scalar(Slice{digest.data(), digest.size()});
}

ECPoint
hashToPoint(Slice const& domain, Slice const& data)
{
    for (std::uint32_t ctr = 0;; ++ctr)
    {
        OpensslSha256Hasher h;
        h(domain.data(), domain.size());
        h(data.data(), data.size());
        std::uint8_t const cb[4] = {
            static_cast<std::uint8_t>(ctr >> 24),
            static_cast<std::uint8_t>(ctr >> 16),
            static_cast<std::uint8_t>(ctr >> 8),
            static_cast<std::uint8_t>(ctr)};
        h(cb, sizeof(cb));
        auto const digest = OpensslSha256Hasher::result_type(h);

        std::array<std::uint8_t, kPointSize> cand{};
        cand[0] = 0x02;
        std::memcpy(cand.data() + 1, digest.data(), digest.size());
        if (auto p = ECPoint::deserialize(Slice{cand.data(), cand.size()}))
            return *p;

        if (ctr == 0xFFFFFFFF)
            Throw<std::runtime_error>("hashToPoint: unable to find point");
    }
}

}  // namespace cmpt
}  // namespace xrpl
