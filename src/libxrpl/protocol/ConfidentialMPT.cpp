#include <xrpl/protocol/ConfidentialMPT.h>

#include <xrpl/basics/contract.h>

#include <secp256k1_mpt.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Verify mpt-crypto linkage: compact proof sizes match our stubs.
static_assert(SECP256K1_POK_SK_PROOF_SIZE == 64);
static_assert(SECP256K1_COMPACT_STANDARD_PROOF_SIZE == 192);
static_assert(SECP256K1_COMPACT_CLAWBACK_PROOF_SIZE == 64);
static_assert(SECP256K1_COMPACT_CONVERTBACK_PROOF_SIZE == 128);

namespace xrpl {
namespace cmpt {

namespace {

template <std::size_t N>
Slice
lit(char const (&s)[N])
{
    return Slice{reinterpret_cast<std::uint8_t const*>(s), N - 1};
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
// RangeProof (aggregated Bulletproof with inner-product argument)
//------------------------------------------------------------------------------

namespace {

// Domain separator for every Fiat-Shamir challenge in the range proof.
inline Slice
rpDomain()
{
    return lit("XLS96-MPT/range/bp/v1");
}

// Number of inner-product recursion rounds needed to fold n elements:
// ceil(log2(n)). n is always a power of two here (bits in {1..64} rounded up).
std::size_t
log2ceil(std::size_t n)
{
    std::size_t k = 0;
    std::size_t p = 1;
    while (p < n)
    {
        p <<= 1;
        ++k;
    }
    return k;
}

// Round bits up to the next power of two (1,2,4,...,64). bits in [1, 64].
std::size_t
padTo(std::uint8_t bits)
{
    std::size_t p = 1;
    while (p < bits)
        p <<= 1;
    return p;
}

// Nothing-up-my-sleeve generator vectors G_i, H_i and the inner-product base
// point U, all derived deterministically from the bit width via hashToPoint.
struct Gens
{
    std::vector<ECPoint> g;
    std::vector<ECPoint> h;
    ECPoint u;
};

Gens
makeGens(std::size_t n)
{
    Gens out;
    out.g.reserve(n);
    out.h.reserve(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        std::array<std::uint8_t, 9> d{};
        d[0] = 'G';
        for (int j = 0; j < 8; ++j)
            d[1 + j] = static_cast<std::uint8_t>((i >> (8 * j)) & 0xff);
        out.g.push_back(hashToPoint(rpDomain(), Slice{d.data(), d.size()}));
        d[0] = 'H';
        out.h.push_back(hashToPoint(rpDomain(), Slice{d.data(), d.size()}));
    }
    char const u[] = "U";
    out.u = hashToPoint(
        rpDomain(), Slice{reinterpret_cast<std::uint8_t const*>(u), 1});
    return out;
}

// Multi-scalar multiplication sum_i s_i * P_i.
ECPoint
msm(std::vector<Scalar> const& s, std::vector<ECPoint> const& p)
{
    ECPoint acc = ECPoint::infinity();
    for (std::size_t i = 0; i < s.size(); ++i)
        acc = acc + ECPoint::mul(s[i], p[i]);
    return acc;
}

// Inner product <a, b> = sum_i a_i b_i.
Scalar
inner(std::vector<Scalar> const& a, std::vector<Scalar> const& b)
{
    Scalar acc;
    for (std::size_t i = 0; i < a.size(); ++i)
        acc = acc + a[i] * b[i];
    return acc;
}

// Append a point's compressed bytes to a Fiat-Shamir transcript buffer.
void
absorb(std::vector<std::uint8_t>& t, ECPoint const& p)
{
    auto const b = p.serialize();
    t.insert(t.end(), b.begin(), b.end());
}

// Append a scalar's bytes to a Fiat-Shamir transcript buffer.
void
absorb(std::vector<std::uint8_t>& t, Scalar const& s)
{
    t.insert(t.end(), s.bytes().begin(), s.bytes().end());
}

}  // namespace

std::size_t
RangeProof::rounds(std::uint8_t bits)
{
    return log2ceil(padTo(bits));
}

std::size_t
RangeProof::serializedSize(std::uint8_t bits)
{
    // 1 width byte + A,S,T1,T2 + tauX,mu,tHat + 2k IPA points + a,b.
    return 1 + 4 * kPointSize + 3 * kScalarSize +
        2 * rounds(bits) * kPointSize + 2 * kScalarSize;
}

std::pair<RangeProof, PedersenCommitment>
RangeProof::prove(std::uint64_t value, Scalar const& blind, std::uint8_t bits)
{
    if (bits == 0 || bits > kMaxBits)
        Throw<std::runtime_error>("RangeProof::prove: invalid bit width");

    PedersenCommitment const commitment =
        PedersenCommitment::commit(value, blind);

    std::size_t const n = padTo(bits);
    Gens const gen = makeGens(n);
    ECPoint const H = ECPoint::generatorH();

    Scalar const one(std::uint64_t{1});

    // aL = bit vector of `value` (positions >= bits are zero, since
    // value < 2^bits is the statement being proven); aR = aL - 1.
    std::vector<Scalar> aL(n);
    std::vector<Scalar> aR(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        std::uint64_t const bit = (i < bits) ? ((value >> i) & 1u) : 0u;
        aL[i] = Scalar(bit);
        aR[i] = aL[i] - one;
    }

    // A = <aL, G> + <aR, H> + alpha*H_base ; S = <sL, G> + <sR, H> + rho*H_base.
    std::vector<Scalar> sL(n);
    std::vector<Scalar> sR(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        sL[i] = Scalar::random();
        sR[i] = Scalar::random();
    }
    Scalar const alpha = Scalar::random();
    Scalar const rho = Scalar::random();

    RangeProof proof;
    proof.bits_ = bits;
    proof.a_ = msm(aL, gen.g) + msm(aR, gen.h) + ECPoint::mul(alpha, H);
    proof.s_ = msm(sL, gen.g) + msm(sR, gen.h) + ECPoint::mul(rho, H);

    // Transcript: commitment || A || S  ->  challenges y, z.
    std::vector<std::uint8_t> t;
    absorb(t, commitment.point());
    absorb(t, proof.a_);
    absorb(t, proof.s_);
    Slice const tSlice0{t.data(), t.size()};
    Scalar const y = hashToScalar(rpDomain(), {tSlice0, lit("y")});
    Scalar const z = hashToScalar(rpDomain(), {tSlice0, lit("z")});

    // Powers y^i (full padded width) and 2^i. The 2^i weights are only set for
    // positions i < bits; padding positions [bits, n) stay zero (default
    // Scalar), so they contribute nothing to the represented value and the
    // proof is bounded by 2^bits rather than 2^n. z2 = z^2.
    std::vector<Scalar> yPow(n);
    std::vector<Scalar> twoPow(n);
    yPow[0] = one;
    for (std::size_t i = 1; i < n; ++i)
        yPow[i] = yPow[i - 1] * y;
    Scalar const two(std::uint64_t{2});
    twoPow[0] = one;
    for (std::size_t i = 1; i < bits; ++i)
        twoPow[i] = twoPow[i - 1] * two;
    Scalar const z2 = z * z;

    // l(X) = (aL - z*1) + sL*X ; r(X) = y^n o (aR + z*1 + sR*X) + z^2 2^n.
    std::vector<Scalar> l0(n), l1(n), r0(n), r1(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        l0[i] = aL[i] - z;
        l1[i] = sL[i];
        r0[i] = yPow[i] * (aR[i] + z) + z2 * twoPow[i];
        r1[i] = yPow[i] * sR[i];
    }

    // t(X) = <l,r> = t0 + t1 X + t2 X^2.
    Scalar const t1c = inner(l0, r1) + inner(l1, r0);
    Scalar const t2c = inner(l1, r1);

    Scalar const tau1 = Scalar::random();
    Scalar const tau2 = Scalar::random();
    proof.t1_ = PedersenCommitment::commit(t1c, tau1).point();
    proof.t2_ = PedersenCommitment::commit(t2c, tau2).point();

    // Transcript: || T1 || T2  ->  challenge x.
    absorb(t, proof.t1_);
    absorb(t, proof.t2_);
    Slice const tSlice1{t.data(), t.size()};
    Scalar const x = hashToScalar(rpDomain(), {tSlice1, lit("x")});

    // Evaluate l, r, tHat at x and the blinding openings.
    std::vector<Scalar> lv(n), rv(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        lv[i] = l0[i] + l1[i] * x;
        rv[i] = r0[i] + r1[i] * x;
    }
    proof.tHat_ = inner(lv, rv);
    proof.tauX_ = z2 * blind + tau1 * x + tau2 * (x * x);
    proof.mu_ = alpha + rho * x;

    // Inner-product argument on (lv, rv) over generators (g, h') where
    // h'_i = (y^{-i}) o h_i, with base point U weighted by challenge w.
    auto const yInv = y.invert();
    if (!yInv)
        Throw<std::runtime_error>("RangeProof::prove: non-invertible y");
    std::vector<ECPoint> gv = gen.g;
    std::vector<ECPoint> hv(n);
    Scalar yInvPow = one;
    for (std::size_t i = 0; i < n; ++i)
    {
        hv[i] = ECPoint::mul(yInvPow, gen.h[i]);
        yInvPow = yInvPow * *yInv;
    }

    // Bind U into the transcript via w = H(transcript || tHat).
    absorb(t, proof.tHat_);
    Slice const tSlice2{t.data(), t.size()};
    Scalar const w = hashToScalar(rpDomain(), {tSlice2, lit("w")});
    ECPoint const U = ECPoint::mul(w, gen.u);

    std::vector<Scalar> a = lv;
    std::vector<Scalar> b = rv;
    std::vector<std::uint8_t> tip = t;  // running IPA transcript

    std::size_t m = n;
    while (m > 1)
    {
        std::size_t const half = m / 2;
        std::vector<Scalar> aLo(a.begin(), a.begin() + half);
        std::vector<Scalar> aHi(a.begin() + half, a.begin() + m);
        std::vector<Scalar> bLo(b.begin(), b.begin() + half);
        std::vector<Scalar> bHi(b.begin() + half, b.begin() + m);
        std::vector<ECPoint> gLo(gv.begin(), gv.begin() + half);
        std::vector<ECPoint> gHi(gv.begin() + half, gv.begin() + m);
        std::vector<ECPoint> hLo(hv.begin(), hv.begin() + half);
        std::vector<ECPoint> hHi(hv.begin() + half, hv.begin() + m);

        Scalar const cL = inner(aLo, bHi);
        Scalar const cR = inner(aHi, bLo);
        ECPoint const L =
            msm(aLo, gHi) + msm(bHi, hLo) + ECPoint::mul(cL, U);
        ECPoint const R =
            msm(aHi, gLo) + msm(bLo, hHi) + ECPoint::mul(cR, U);
        proof.ipL_.push_back(L);
        proof.ipR_.push_back(R);

        absorb(tip, L);
        absorb(tip, R);
        Scalar const u = hashToScalar(
            rpDomain(), {Slice{tip.data(), tip.size()}, lit("u")});
        auto const uInv = u.invert();
        if (!uInv)
            Throw<std::runtime_error>("RangeProof::prove: non-invertible u");

        std::vector<Scalar> aNew(half), bNew(half);
        std::vector<ECPoint> gNew(half), hNew(half);
        for (std::size_t i = 0; i < half; ++i)
        {
            aNew[i] = aLo[i] * u + aHi[i] * *uInv;
            bNew[i] = bLo[i] * *uInv + bHi[i] * u;
            gNew[i] = ECPoint::mul(*uInv, gLo[i]) + ECPoint::mul(u, gHi[i]);
            hNew[i] = ECPoint::mul(u, hLo[i]) + ECPoint::mul(*uInv, hHi[i]);
        }
        a = std::move(aNew);
        b = std::move(bNew);
        gv = std::move(gNew);
        hv = std::move(hNew);
        m = half;
    }

    proof.ipa_ = a[0];
    proof.ipb_ = b[0];
    return {proof, commitment};
}

bool
RangeProof::verify(PedersenCommitment const& commitment) const
{
    if (bits_ == 0 || bits_ > kMaxBits)
        return false;
    std::size_t const n = padTo(bits_);
    if (ipL_.size() != rounds(bits_) || ipR_.size() != ipL_.size())
        return false;

    Gens const gen = makeGens(n);
    ECPoint const H = ECPoint::generatorH();
    Scalar const one(std::uint64_t{1});

    // Recompute challenges y, z, x, w from the transcript.
    std::vector<std::uint8_t> t;
    absorb(t, commitment.point());
    absorb(t, a_);
    absorb(t, s_);
    Slice const tSlice0{t.data(), t.size()};
    Scalar const y = hashToScalar(rpDomain(), {tSlice0, lit("y")});
    Scalar const z = hashToScalar(rpDomain(), {tSlice0, lit("z")});

    absorb(t, t1_);
    absorb(t, t2_);
    Slice const tSlice1{t.data(), t.size()};
    Scalar const x = hashToScalar(rpDomain(), {tSlice1, lit("x")});

    // Mirror the prover: 2^i weights only for positions i < bits_; padding
    // positions [bits_, n) stay zero so they contribute nothing to the
    // represented value (bounds the proof by 2^bits_, not 2^n).
    std::vector<Scalar> yPow(n);
    std::vector<Scalar> twoPow(n);
    yPow[0] = one;
    for (std::size_t i = 1; i < n; ++i)
        yPow[i] = yPow[i - 1] * y;
    Scalar const two(std::uint64_t{2});
    twoPow[0] = one;
    for (std::size_t i = 1; i < bits_; ++i)
        twoPow[i] = twoPow[i - 1] * two;
    Scalar const z2 = z * z;
    Scalar const z3 = z2 * z;

    // sum_i y^i and sum_i 2^i.
    Scalar sumY;
    Scalar sumTwo;
    for (std::size_t i = 0; i < n; ++i)
    {
        sumY = sumY + yPow[i];
        sumTwo = sumTwo + twoPow[i];
    }

    // delta(y,z) = (z - z^2) * sum y^i - z^3 * sum 2^i.
    Scalar const delta = (z - z2) * sumY - z3 * sumTwo;

    // Check t-poly opening: tHat*G + tauX*H == V*z^2 + delta*G + x*T1 + x^2*T2.
    ECPoint const lhsT =
        ECPoint::mulBase(tHat_) + ECPoint::mul(tauX_, H);
    ECPoint const rhsT = ECPoint::mul(z2, commitment.point()) +
        ECPoint::mulBase(delta) + ECPoint::mul(x, t1_) +
        ECPoint::mul(x * x, t2_);
    if (lhsT != rhsT)
        return false;

    // Rebuild h'_i = y^{-i} o h_i.
    auto const yInv = y.invert();
    if (!yInv)
        return false;
    std::vector<ECPoint> gv = gen.g;
    std::vector<ECPoint> hv(n);
    Scalar yInvPow = one;
    for (std::size_t i = 0; i < n; ++i)
    {
        hv[i] = ECPoint::mul(yInvPow, gen.h[i]);
        yInvPow = yInvPow * *yInv;
    }

    // w binds U; P0 is the IPA commitment to (l, r) with the value tHat folded
    // into U: P0 = A + x*S - mu*H_base + <(z)*1, g_offset> + ... reconstructed
    // directly from the round equation below.
    absorb(t, tHat_);
    Slice const tSlice2{t.data(), t.size()};
    Scalar const w = hashToScalar(rpDomain(), {tSlice2, lit("w")});
    ECPoint const U = ECPoint::mul(w, gen.u);

    // P = A + x*S - mu*H + sum_i [ z*g_i ] + sum_i [ (z*y^i + z^2 2^i) * h'_i ]
    //     + tHat*U  (the committed inner product).
    std::vector<Scalar> gExp(n);
    std::vector<Scalar> hExp(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        gExp[i] = z.negate();
        hExp[i] = z * yPow[i] + z2 * twoPow[i];
    }
    ECPoint P = a_ + ECPoint::mul(x, s_) + ECPoint::mul(mu_.negate(), H) +
        msm(gExp, gv) + msm(hExp, hv) + ECPoint::mul(tHat_, U);

    // Replay the IPA rounds, folding generators and P with each challenge u.
    std::vector<std::uint8_t> tip = t;
    std::vector<Scalar> uChal(ipL_.size());
    std::vector<Scalar> uInvChal(ipL_.size());
    for (std::size_t r = 0; r < ipL_.size(); ++r)
    {
        absorb(tip, ipL_[r]);
        absorb(tip, ipR_[r]);
        Scalar const u = hashToScalar(
            rpDomain(), {Slice{tip.data(), tip.size()}, lit("u")});
        auto const uInv = u.invert();
        if (!uInv)
            return false;
        uChal[r] = u;
        uInvChal[r] = *uInv;
    }

    // Fold generators down to a single g* and h* using the standard product of
    // challenges. s_i = prod_j u_j^{ +1 if bit set else -1 }.
    std::size_t const k = ipL_.size();
    std::vector<Scalar> sVec(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        Scalar prod = one;
        for (std::size_t j = 0; j < k; ++j)
        {
            // Round j (from first) folds with stride; the high half (bit set)
            // uses u, the low half uses u^{-1}. Bit ordering matches the
            // prover's split: most-significant round is j = 0.
            std::size_t const bitMask = std::size_t{1} << (k - 1 - j);
            bool const hi = (i & bitMask) != 0;
            prod = prod * (hi ? uChal[j] : uInvChal[j]);
        }
        sVec[i] = prod;
    }

    ECPoint gStar = ECPoint::infinity();
    ECPoint hStar = ECPoint::infinity();
    for (std::size_t i = 0; i < n; ++i)
    {
        gStar = gStar + ECPoint::mul(sVec[i], gv[i]);
        // h folds with the inverse pattern of g.
        Scalar const sInv = sVec[i].invert().value_or(Scalar());
        hStar = hStar + ECPoint::mul(sInv, hv[i]);
    }

    // Fold P with L_j, R_j: P' = P + sum_j (u_j^2 L_j + u_j^{-2} R_j).
    ECPoint Pfold = P;
    for (std::size_t r = 0; r < k; ++r)
    {
        Scalar const u2 = uChal[r] * uChal[r];
        Scalar const u2Inv = uInvChal[r] * uInvChal[r];
        Pfold = Pfold + ECPoint::mul(u2, ipL_[r]) + ECPoint::mul(u2Inv, ipR_[r]);
    }

    // Final check: P' == a*g* + b*h* + (a*b)*U.
    ECPoint const rhs = ECPoint::mul(ipa_, gStar) +
        ECPoint::mul(ipb_, hStar) + ECPoint::mul(ipa_ * ipb_, U);
    return Pfold == rhs;
}

std::vector<std::uint8_t>
RangeProof::serialize() const
{
    std::vector<std::uint8_t> out;
    out.reserve(serializedSize(bits_));
    out.push_back(bits_);
    for (ECPoint const* p : {&a_, &s_, &t1_, &t2_})
    {
        auto const b = p->serialize();
        out.insert(out.end(), b.begin(), b.end());
    }
    for (Scalar const* s : {&tauX_, &mu_, &tHat_})
        out.insert(out.end(), s->bytes().begin(), s->bytes().end());
    for (auto const& L : ipL_)
    {
        auto const b = L.serialize();
        out.insert(out.end(), b.begin(), b.end());
    }
    for (auto const& R : ipR_)
    {
        auto const b = R.serialize();
        out.insert(out.end(), b.begin(), b.end());
    }
    out.insert(out.end(), ipa_.bytes().begin(), ipa_.bytes().end());
    out.insert(out.end(), ipb_.bytes().begin(), ipb_.bytes().end());
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
    if (in.size() != serializedSize(bits))
        return std::nullopt;

    RangeProof proof;
    proof.bits_ = bits;
    std::size_t off = 1;

    auto readPoint = [&](ECPoint& dst) -> bool {
        auto const p = ECPoint::deserialize(Slice{in.data() + off, kPointSize});
        if (!p)
            return false;
        dst = *p;
        off += kPointSize;
        return true;
    };
    auto readScalar = [&](Scalar& dst) {
        dst = Scalar{Slice{in.data() + off, kScalarSize}};
        off += kScalarSize;
    };

    if (!readPoint(proof.a_) || !readPoint(proof.s_) ||
        !readPoint(proof.t1_) || !readPoint(proof.t2_))
        return std::nullopt;
    readScalar(proof.tauX_);
    readScalar(proof.mu_);
    readScalar(proof.tHat_);

    std::size_t const k = rounds(bits);
    proof.ipL_.resize(k);
    proof.ipR_.resize(k);
    for (std::size_t i = 0; i < k; ++i)
        if (!readPoint(proof.ipL_[i]))
            return std::nullopt;
    for (std::size_t i = 0; i < k; ++i)
        if (!readPoint(proof.ipR_[i]))
            return std::nullopt;
    readScalar(proof.ipa_);
    readScalar(proof.ipb_);
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

//------------------------------------------------------------------------------
// CompactStandardProof (stub for XLS-0096 Phase 1)
//------------------------------------------------------------------------------

// TODO(#14): implement compact AND-composed sigma (mpt-crypto proof_compact_standard.c)
CompactStandardProof
CompactStandardProof::prove(
    Scalar const&,
    std::uint64_t,
    std::uint64_t,
    Scalar const&,
    Scalar const&,
    Scalar const&,
    ElGamalPublicKey const&,
    ElGamalCiphertext const&,
    ElGamalCiphertext const&,
    PedersenCommitment const&,
    PedersenCommitment const&)
{
    return CompactStandardProof{};
}

// TODO(#14): implement compact AND-composed sigma (mpt-crypto proof_compact_standard.c)
bool
CompactStandardProof::verify(
    ElGamalPublicKey const&,
    ElGamalPublicKey const&,
    ElGamalCiphertext const&,
    ElGamalCiphertext const&,
    PedersenCommitment const&,
    PedersenCommitment const&) const
{
    return false;
}

std::array<std::uint8_t, CompactStandardProof::kSize>
CompactStandardProof::serialize() const
{
    return data_;
}

std::optional<CompactStandardProof>
CompactStandardProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    CompactStandardProof proof;
    std::memcpy(proof.data_.data(), in.data(), kSize);
    return proof;
}

}  // namespace cmpt
}  // namespace xrpl
