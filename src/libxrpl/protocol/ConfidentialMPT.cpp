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
    // Reject the identity/all-zero public key: it would zero the k*Y mask,
    // leaving c2 = m*G and making the plaintext recoverable without the key.
    if (pub.isInfinity())
        Throw<std::runtime_error>(
            "ElGamalCiphertext::encrypt: identity public key");

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

ElGamalCiphertext
ElGamalCiphertext::operator-(ElGamalCiphertext const& o) const
{
    return ElGamalCiphertext{c1_ - o.c1_, c2_ - o.c2_};
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
    // Never produce a proof for the identity key (secret == 0). Such a key
    // removes the EC-ElGamal mask, so accepting it enables a rogue-key attack.
    if (secret.isZero() || pub.isInfinity())
        Throw<std::runtime_error>(
            "SchnorrProof::prove: identity/zero public key");

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
    // Reject the identity/all-zero public key before any algebra: with pub at
    // infinity the e*Y term vanishes, so a proof for the zero secret would
    // otherwise verify (rogue-key attack).
    if (pub.isInfinity())
        return false;

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

//------------------------------------------------------------------------------
// LinkageProof (secret-key ElGamal <-> Pedersen linkage)
//------------------------------------------------------------------------------

LinkageProof
LinkageProof::prove(
    Scalar const& secret,
    std::uint64_t value,
    Scalar const& blind,
    ElGamalCiphertext const& ct,
    PedersenCommitment const& commitment)
{
    ECPoint const H = ECPoint::generatorH();
    ECPoint const Y = ECPoint::mulBase(secret);
    Scalar const m(value);

    Scalar const a = Scalar::random();  // for the secret key x
    Scalar const b = Scalar::random();  // for the value m
    Scalar const d = Scalar::random();  // for the blinding r

    ECPoint const t1 = ECPoint::mulBase(a);
    ECPoint const t2 = ECPoint::mulBase(b) + ECPoint::mul(a, ct.c1());
    ECPoint const t3 = ECPoint::mulBase(b) + ECPoint::mul(d, H);

    auto const yb = Y.serialize();
    auto const c1b = ct.c1().serialize();
    auto const c2b = ct.c2().serialize();
    auto const pb = commitment.point().serialize();
    auto const t1b = t1.serialize();
    auto const t2b = t2.serialize();
    auto const t3b = t3.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/link/v1"),
        {Slice{yb.data(), yb.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{pb.data(), pb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()},
         Slice{t3b.data(), t3b.size()}});

    Scalar const zx = a + e * secret;
    Scalar const zm = b + e * m;
    Scalar const zr = d + e * blind;
    return LinkageProof{e, zx, zm, zr};
}

bool
LinkageProof::verify(
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& ct,
    PedersenCommitment const& commitment) const
{
    // Reject the identity public key: with Y at infinity the e*Y term vanishes
    // and a proof for the zero secret could otherwise verify.
    if (pub.isInfinity())
        return false;

    ECPoint const H = ECPoint::generatorH();

    ECPoint const t1 = ECPoint::mulBase(zx_) - ECPoint::mul(e_, pub);
    ECPoint const t2 = ECPoint::mulBase(zm_) + ECPoint::mul(zx_, ct.c1()) -
        ECPoint::mul(e_, ct.c2());
    ECPoint const t3 = ECPoint::mulBase(zm_) + ECPoint::mul(zr_, H) -
        ECPoint::mul(e_, commitment.point());

    auto const yb = pub.serialize();
    auto const c1b = ct.c1().serialize();
    auto const c2b = ct.c2().serialize();
    auto const pb = commitment.point().serialize();
    auto const t1b = t1.serialize();
    auto const t2b = t2.serialize();
    auto const t3b = t3.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/link/v1"),
        {Slice{yb.data(), yb.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{pb.data(), pb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()},
         Slice{t3b.data(), t3b.size()}});
    return e == e_;
}

std::array<std::uint8_t, LinkageProof::kSize>
LinkageProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, zx_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 2 * kScalarSize, zm_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 3 * kScalarSize, zr_.bytes().data(), kScalarSize);
    return out;
}

std::optional<LinkageProof>
LinkageProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const zx{Slice{in.data() + kScalarSize, kScalarSize}};
    Scalar const zm{Slice{in.data() + 2 * kScalarSize, kScalarSize}};
    Scalar const zr{Slice{in.data() + 3 * kScalarSize, kScalarSize}};
    return LinkageProof{e, zx, zm, zr};
}

//------------------------------------------------------------------------------
// PlaintextEqualityProof (two EC-ElGamal ciphertexts, same plaintext)
//------------------------------------------------------------------------------

PlaintextEqualityProof
PlaintextEqualityProof::prove(
    ElGamalPublicKey const& pub1,
    ElGamalPublicKey const& pub2,
    std::uint64_t value,
    Scalar const& k1,
    Scalar const& k2,
    ElGamalCiphertext const& ct1,
    ElGamalCiphertext const& ct2)
{
    Scalar const m(value);

    Scalar const wm = Scalar::random();
    Scalar const w1 = Scalar::random();
    Scalar const w2 = Scalar::random();

    ECPoint const a1 = ECPoint::mulBase(w1);
    ECPoint const a2 = ECPoint::mulBase(wm) + ECPoint::mul(w1, pub1);
    ECPoint const b1 = ECPoint::mulBase(w2);
    ECPoint const b2 = ECPoint::mulBase(wm) + ECPoint::mul(w2, pub2);

    auto const y1b = pub1.serialize();
    auto const y2b = pub2.serialize();
    auto const c1a = ct1.c1().serialize();
    auto const c1b = ct1.c2().serialize();
    auto const c2a = ct2.c1().serialize();
    auto const c2b = ct2.c2().serialize();
    auto const a1b = a1.serialize();
    auto const a2b = a2.serialize();
    auto const b1b = b1.serialize();
    auto const b2b = b2.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/pteq/v1"),
        {Slice{y1b.data(), y1b.size()},
         Slice{y2b.data(), y2b.size()},
         Slice{c1a.data(), c1a.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2a.data(), c2a.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{a1b.data(), a1b.size()},
         Slice{a2b.data(), a2b.size()},
         Slice{b1b.data(), b1b.size()},
         Slice{b2b.data(), b2b.size()}});

    Scalar const zm = wm + e * m;
    Scalar const z1 = w1 + e * k1;
    Scalar const z2 = w2 + e * k2;
    return PlaintextEqualityProof{e, zm, z1, z2};
}

bool
PlaintextEqualityProof::verify(
    ElGamalPublicKey const& pub1,
    ElGamalPublicKey const& pub2,
    ElGamalCiphertext const& ct1,
    ElGamalCiphertext const& ct2) const
{
    if (pub1.isInfinity() || pub2.isInfinity())
        return false;

    ECPoint const a1 = ECPoint::mulBase(z1_) - ECPoint::mul(e_, ct1.c1());
    ECPoint const a2 = ECPoint::mulBase(zm_) + ECPoint::mul(z1_, pub1) -
        ECPoint::mul(e_, ct1.c2());
    ECPoint const b1 = ECPoint::mulBase(z2_) - ECPoint::mul(e_, ct2.c1());
    ECPoint const b2 = ECPoint::mulBase(zm_) + ECPoint::mul(z2_, pub2) -
        ECPoint::mul(e_, ct2.c2());

    auto const y1b = pub1.serialize();
    auto const y2b = pub2.serialize();
    auto const c1a = ct1.c1().serialize();
    auto const c1b = ct1.c2().serialize();
    auto const c2a = ct2.c1().serialize();
    auto const c2b = ct2.c2().serialize();
    auto const a1b = a1.serialize();
    auto const a2b = a2.serialize();
    auto const b1b = b1.serialize();
    auto const b2b = b2.serialize();
    Scalar const e = hashToScalar(
        lit("XLS96-MPT/pteq/v1"),
        {Slice{y1b.data(), y1b.size()},
         Slice{y2b.data(), y2b.size()},
         Slice{c1a.data(), c1a.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2a.data(), c2a.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{a1b.data(), a1b.size()},
         Slice{a2b.data(), a2b.size()},
         Slice{b1b.data(), b1b.size()},
         Slice{b2b.data(), b2b.size()}});
    return e == e_;
}

std::array<std::uint8_t, PlaintextEqualityProof::kSize>
PlaintextEqualityProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, zm_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 2 * kScalarSize, z1_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 3 * kScalarSize, z2_.bytes().data(), kScalarSize);
    return out;
}

std::optional<PlaintextEqualityProof>
PlaintextEqualityProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const zm{Slice{in.data() + kScalarSize, kScalarSize}};
    Scalar const z1{Slice{in.data() + 2 * kScalarSize, kScalarSize}};
    Scalar const z2{Slice{in.data() + 3 * kScalarSize, kScalarSize}};
    return PlaintextEqualityProof{e, zm, z1, z2};
}

}  // namespace cmpt
}  // namespace xrpl
