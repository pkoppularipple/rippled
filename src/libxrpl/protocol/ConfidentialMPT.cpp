#include <xrpl/protocol/ConfidentialMPT.h>

#include <xrpl/basics/contract.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace xrpl {
namespace cmpt {

namespace {

template <std::size_t N>
Slice
lit(char const (&s)[N])
{
    return Slice{reinterpret_cast<std::uint8_t const*>(s), N - 1};
}

// 2^i as a scalar (i < 64).
Scalar
pow2(unsigned i)
{
    return Scalar(std::uint64_t{1} << i);
}

std::string
key(ECPoint const& p)
{
    auto const b = p.serialize();
    return std::string(reinterpret_cast<char const*>(b.data()), b.size());
}

}  // namespace

//------------------------------------------------------------------------------
// PedersenCommitment
//------------------------------------------------------------------------------

PedersenCommitment
PedersenCommitment::commit(std::uint64_t value, Scalar const& blind)
{
    return commit(Scalar(value), blind);
}

PedersenCommitment
PedersenCommitment::commit(Scalar const& value, Scalar const& blind)
{
    ECPoint const c =
        ECPoint::mulBase(value) + ECPoint::mul(blind, ECPoint::generatorH());
    return PedersenCommitment{c};
}

PedersenCommitment
PedersenCommitment::operator+(PedersenCommitment const& o) const
{
    return PedersenCommitment{c_ + o.c_};
}

bool
PedersenCommitment::operator==(PedersenCommitment const& o) const
{
    return c_ == o.c_;
}

std::array<std::uint8_t, kPointSize>
PedersenCommitment::serialize() const
{
    return c_.serialize();
}

std::optional<PedersenCommitment>
PedersenCommitment::deserialize(Slice const& in)
{
    if (auto p = ECPoint::deserialize(in))
        return PedersenCommitment{*p};
    return std::nullopt;
}

//------------------------------------------------------------------------------
// EC-ElGamal
//------------------------------------------------------------------------------

ElGamalSecretKey
ElGamalSecretKey::random()
{
    Scalar x = Scalar::random();
    while (x.isZero())
        x = Scalar::random();
    return ElGamalSecretKey{x};
}

ElGamalPublicKey
ElGamalSecretKey::publicKey() const
{
    return ECPoint::mulBase(x);
}

ElGamalCiphertext
ElGamalCiphertext::encrypt(
    ElGamalPublicKey const& pub,
    std::uint64_t m,
    Scalar const& k)
{
    ECPoint const c1 = ECPoint::mulBase(k);
    ECPoint const c2 = ECPoint::mulBase(Scalar(m)) + ECPoint::mul(k, pub);
    return ElGamalCiphertext{c1, c2};
}

ElGamalCiphertext
ElGamalCiphertext::encrypt(ElGamalPublicKey const& pub, std::uint64_t m)
{
    return encrypt(pub, m, Scalar::random());
}

ElGamalCiphertext
ElGamalCiphertext::encryptZero()
{
    return ElGamalCiphertext{ECPoint::infinity(), ECPoint::infinity()};
}

ElGamalCiphertext
ElGamalCiphertext::operator+(ElGamalCiphertext const& o) const
{
    return ElGamalCiphertext{c1_ + o.c1_, c2_ + o.c2_};
}

ECPoint
ElGamalCiphertext::decryptToPoint(Scalar const& secret) const
{
    return c2_ - ECPoint::mul(secret, c1_);
}

bool
ElGamalCiphertext::operator==(ElGamalCiphertext const& o) const
{
    return c1_ == o.c1_ && c2_ == o.c2_;
}

std::optional<std::uint64_t>
ElGamalCiphertext::decrypt(Scalar const& secret, std::uint64_t maxValue) const
{
    // M = m*G; recover m in [0, maxValue] via baby-step/giant-step.
    ECPoint const m = decryptToPoint(secret);

    std::uint64_t giant = 1;
    while (giant <= maxValue / giant)
        ++giant;  // smallest giant with giant^2 > maxValue

    std::unordered_map<std::string, std::uint64_t> baby;
    ECPoint step = ECPoint::infinity();  // j*G
    for (std::uint64_t j = 0; j < giant; ++j)
    {
        baby.emplace(key(step), j);
        step = step + ECPoint::base();
    }

    ECPoint const factor = ECPoint::mulBase(Scalar(giant));  // giant*G
    ECPoint cur = m;
    for (std::uint64_t i = 0; i * giant <= maxValue; ++i)
    {
        if (auto it = baby.find(key(cur)); it != baby.end())
        {
            std::uint64_t const v = i * giant + it->second;
            if (v <= maxValue)
                return v;
        }
        cur = cur - factor;
    }
    return std::nullopt;
}

std::array<std::uint8_t, kCiphertextSize>
ElGamalCiphertext::serialize() const
{
    std::array<std::uint8_t, kCiphertextSize> out{};
    auto const a = c1_.serialize();
    auto const b = c2_.serialize();
    std::memcpy(out.data(), a.data(), kPointSize);
    std::memcpy(out.data() + kPointSize, b.data(), kPointSize);
    return out;
}

std::optional<ElGamalCiphertext>
ElGamalCiphertext::deserialize(Slice const& in)
{
    if (in.size() != kCiphertextSize)
        return std::nullopt;
    auto const c1 = ECPoint::deserialize(Slice{in.data(), kPointSize});
    auto const c2 =
        ECPoint::deserialize(Slice{in.data() + kPointSize, kPointSize});
    if (!c1 || !c2)
        return std::nullopt;
    return ElGamalCiphertext{*c1, *c2};
}

//------------------------------------------------------------------------------
// SchnorrProof (proof of knowledge of an encryption secret key)
//------------------------------------------------------------------------------

SchnorrProof
SchnorrProof::prove(Scalar const& secret, ElGamalPublicKey const& pub)
{
    Scalar const w = Scalar::random();
    ECPoint const t = ECPoint::mulBase(w);  // commitment A = w*G
    auto const pb = pub.serialize();
    auto const tb = t.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/PoK/v1"),
        {Slice{pb.data(), pb.size()}, Slice{tb.data(), tb.size()}});
    Scalar const s = w + e * secret;
    return SchnorrProof{e, s};
}

bool
SchnorrProof::verify(ElGamalPublicKey const& pub) const
{
    // A' = s*G - e*Y
    ECPoint const t = ECPoint::mulBase(s_) - ECPoint::mul(e_, pub);
    auto const pb = pub.serialize();
    auto const tb = t.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/PoK/v1"),
        {Slice{pb.data(), pb.size()}, Slice{tb.data(), tb.size()}});
    return e == e_;
}

std::array<std::uint8_t, SchnorrProof::kSize>
SchnorrProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, s_.bytes().data(), kScalarSize);
    return out;
}

std::optional<SchnorrProof>
SchnorrProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const s{Slice{in.data() + kScalarSize, kScalarSize}};
    return SchnorrProof{e, s};
}

//------------------------------------------------------------------------------
// RangeProof (bit-decomposition Schnorr-OR range proof)
//------------------------------------------------------------------------------

std::pair<RangeProof, PedersenCommitment>
RangeProof::prove(std::uint64_t value, Scalar const& blind, std::uint8_t bits)
{
    if (bits == 0 || bits > kMaxBits)
        Throw<std::runtime_error>("RangeProof::prove: invalid bit width");

    PedersenCommitment const commitment =
        PedersenCommitment::commit(value, blind);

    ECPoint const G = ECPoint::base();
    ECPoint const H = ECPoint::generatorH();

    // Per-bit blindings r_i chosen so that sum_i 2^i r_i == blind, which makes
    // sum_i 2^i C_i == commitment.
    std::vector<Scalar> r(bits);
    Scalar acc;  // sum_{i<last} 2^i r_i
    for (std::uint8_t i = 0; i + 1 < bits; ++i)
    {
        r[i] = Scalar::random();
        acc = acc + pow2(i) * r[i];
    }
    auto const invLast = pow2(bits - 1).invert();
    if (!invLast)
        Throw<std::runtime_error>("RangeProof::prove: non-invertible weight");
    r[bits - 1] = (blind - acc) * *invLast;

    RangeProof proof;
    proof.bits_ = bits;
    proof.bitProofs_.reserve(bits);

    auto const cb = commitment.serialize();
    Slice const cSlice{cb.data(), cb.size()};

    for (std::uint8_t i = 0; i < bits; ++i)
    {
        unsigned const b = (value >> i) & 1u;
        ECPoint const Ci =
            PedersenCommitment::commit(std::uint64_t{b}, r[i]).point();

        // Branch statements: P0 = Ci (== r_i*H), P1 = Ci - G (== r_i*H).
        std::array<ECPoint, 2> const P = {Ci, Ci - G};

        // Simulate the fake branch f = 1 - b.
        unsigned const f = 1u - b;
        Scalar const cFake = Scalar::random();
        Scalar const zFake = Scalar::random();
        ECPoint const aFake = ECPoint::mul(zFake, H) - ECPoint::mul(cFake, P[f]);

        // Honest commitment for the real branch.
        Scalar const w = Scalar::random();
        ECPoint const aReal = ECPoint::mul(w, H);

        std::array<ECPoint, 2> A;
        A[b] = aReal;
        A[f] = aFake;

        std::uint8_t const idx = i;
        auto const a0 = A[0].serialize();
        auto const a1 = A[1].serialize();
        auto const cib = Ci.serialize();
        Scalar const e = hashToScalar(
            lit("XLS96-MPT/range/v1"),
            {cSlice,
             Slice{&idx, 1},
             Slice{cib.data(), cib.size()},
             Slice{a0.data(), a0.size()},
             Slice{a1.data(), a1.size()}});

        Scalar const cReal = e - cFake;
        Scalar const zReal = w + cReal * r[i];

        std::array<Scalar, 2> c;
        std::array<Scalar, 2> z;
        c[b] = cReal;
        c[f] = cFake;
        z[b] = zReal;
        z[f] = zFake;

        proof.bitProofs_.push_back(BitProof{Ci, c[0], c[1], z[0], z[1]});
    }

    return {proof, commitment};
}

bool
RangeProof::verify(PedersenCommitment const& commitment) const
{
    if (bits_ == 0 || bits_ > kMaxBits || bitProofs_.size() != bits_)
        return false;

    ECPoint const G = ECPoint::base();
    ECPoint const H = ECPoint::generatorH();

    auto const cb = commitment.serialize();
    Slice const cSlice{cb.data(), cb.size()};

    ECPoint aggregate = ECPoint::infinity();
    for (std::uint8_t i = 0; i < bits_; ++i)
    {
        BitProof const& bp = bitProofs_[i];
        std::array<ECPoint, 2> const P = {bp.commitment, bp.commitment - G};

        // A_j = z_j*H - c_j*P_j
        std::array<ECPoint, 2> const A = {
            ECPoint::mul(bp.z0, H) - ECPoint::mul(bp.c0, P[0]),
            ECPoint::mul(bp.z1, H) - ECPoint::mul(bp.c1, P[1])};

        std::uint8_t const idx = i;
        auto const a0 = A[0].serialize();
        auto const a1 = A[1].serialize();
        auto const cib = bp.commitment.serialize();
        Scalar const e = hashToScalar(
            lit("XLS96-MPT/range/v1"),
            {cSlice,
             Slice{&idx, 1},
             Slice{cib.data(), cib.size()},
             Slice{a0.data(), a0.size()},
             Slice{a1.data(), a1.size()}});

        if (e != (bp.c0 + bp.c1))
            return false;

        aggregate = aggregate + ECPoint::mul(pow2(i), bp.commitment);
    }

    return aggregate == commitment.point();
}

std::vector<std::uint8_t>
RangeProof::serialize() const
{
    std::vector<std::uint8_t> out;
    out.reserve(1 + bitProofs_.size() * (kPointSize + 4 * kScalarSize));
    out.push_back(bits_);
    for (auto const& bp : bitProofs_)
    {
        auto const c = bp.commitment.serialize();
        out.insert(out.end(), c.begin(), c.end());
        for (Scalar const* s : {&bp.c0, &bp.c1, &bp.z0, &bp.z1})
            out.insert(out.end(), s->bytes().begin(), s->bytes().end());
    }
    return out;
}

std::optional<RangeProof>
RangeProof::deserialize(Slice const& in)
{
    if (in.size() < 1)
        return std::nullopt;
    std::uint8_t const bits = in.data()[0];
    if (bits == 0 || bits > kMaxBits)
        return std::nullopt;
    std::size_t const recSize = kPointSize + 4 * kScalarSize;
    if (in.size() != 1 + std::size_t{bits} * recSize)
        return std::nullopt;

    RangeProof proof;
    proof.bits_ = bits;
    proof.bitProofs_.reserve(bits);
    std::size_t off = 1;
    for (std::uint8_t i = 0; i < bits; ++i)
    {
        auto const c = ECPoint::deserialize(Slice{in.data() + off, kPointSize});
        if (!c)
            return std::nullopt;
        off += kPointSize;
        Scalar const c0{Slice{in.data() + off, kScalarSize}};
        off += kScalarSize;
        Scalar const c1{Slice{in.data() + off, kScalarSize}};
        off += kScalarSize;
        Scalar const z0{Slice{in.data() + off, kScalarSize}};
        off += kScalarSize;
        Scalar const z1{Slice{in.data() + off, kScalarSize}};
        off += kScalarSize;
        proof.bitProofs_.push_back(BitProof{*c, c0, c1, z0, z1});
    }
    return proof;
}

}  // namespace cmpt
}  // namespace xrpl
