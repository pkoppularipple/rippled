#include <xrpl/protocol/ConfidentialMPT.h>

#include <xrpl/basics/contract.h>
#include <xrpl/protocol/digest.h>

#include <secp256k1_mpt.h>
#include <utility/mpt_utility.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

// Verify mpt-crypto linkage: compact proof sizes match the reference library.
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

// SHA-256 Fiat-Shamir challenge shared with the compact sigma proofs and the
// registration PoK: e = reduce32(SHA256(domain || parts || context_id)). The
// 32-byte contextId is appended only when non-empty. Defined later in the
// file; forward-declared here so SchnorrProof can use it.
Scalar
compactChallenge(
    Slice const& domain,
    std::vector<Slice> const& parts,
    Slice const& contextId);

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
SchnorrProof::prove(
    Scalar const& secret,
    ElGamalPublicKey const& pub,
    Slice const& contextId)
{
    // Never produce a proof for the identity key (secret == 0). Such a key
    // removes the EC-ElGamal mask, so accepting it enables a rogue-key attack.
    if (secret.isZero() || pub.isInfinity())
        Throw<std::runtime_error>(
            "SchnorrProof::prove: identity/zero public key");

    Scalar const w = Scalar::random();
    ECPoint const t = ECPoint::mulBase(w);  // commitment T = w*G
    auto const pb = pub.serialize();
    auto const tb = t.serialize();
    Scalar const e = compactChallenge(
        lit("CMPT_POK_SK_REGISTER"),
        {Slice{pb.data(), pb.size()}, Slice{tb.data(), tb.size()}},
        contextId);
    Scalar const s = w + e * secret;
    return SchnorrProof{e, s};
}

bool
SchnorrProof::verify(ElGamalPublicKey const& pub, Slice const& contextId) const
{
    // Reject the identity/all-zero public key before any algebra: with pub at
    // infinity the e*Y term vanishes, so a proof for the zero secret would
    // otherwise verify (rogue-key attack).
    if (pub.isInfinity())
        return false;

    // T = s*G - e*Y
    ECPoint const t = ECPoint::mulBase(s_) - ECPoint::mul(e_, pub);
    auto const pb = pub.serialize();
    auto const tb = t.serialize();
    Scalar const e = compactChallenge(
        lit("CMPT_POK_SK_REGISTER"),
        {Slice{pb.data(), pb.size()}, Slice{tb.data(), tb.size()}},
        contextId);
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
RangeProof::prove(
    std::uint64_t value,
    Scalar const& blind,
    std::uint8_t bits,
    Slice const& contextId)
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

    // Transcript: commitment || A || S [|| context_id]  ->  challenges y, z.
    // The context_id is folded in before the first challenge, so it binds
    // every subsequent challenge (y, z, x, w, and the IPA rounds).
    std::vector<std::uint8_t> t;
    absorb(t, commitment.point());
    absorb(t, proof.a_);
    absorb(t, proof.s_);
    if (contextId.size())
        t.insert(t.end(), contextId.data(), contextId.data() + contextId.size());
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
RangeProof::verify(PedersenCommitment const& commitment, Slice const& contextId)
    const
{
    if (bits_ == 0 || bits_ > kMaxBits)
        return false;
    std::size_t const n = padTo(bits_);
    if (ipL_.size() != rounds(bits_) || ipR_.size() != ipL_.size())
        return false;

    Gens const gen = makeGens(n);
    ECPoint const H = ECPoint::generatorH();
    Scalar const one(std::uint64_t{1});

    // Recompute challenges y, z, x, w from the transcript. The context_id is
    // folded in before the first challenge, mirroring prove().
    std::vector<std::uint8_t> t;
    absorb(t, commitment.point());
    absorb(t, a_);
    absorb(t, s_);
    if (contextId.size())
        t.insert(t.end(), contextId.data(), contextId.data() + contextId.size());
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
// RangeProof: aggregated (multi-value) variant.
//
// An aggregated Bulletproof proves that m committed values each lie in
// [0, 2^bits) while sharing a single inner-product argument over the
// concatenated bit vectors (total width N = padTo(bits) * m). The math is the
// exact generalization of the single-value path above: block j (0-indexed)
// weights its 2^k vector and its value commitment V_j by z^{2+j}, delta(y,z)
// subtracts sum_j z^{3+j} * <1, 2^bits>, and tauX aggregates sum_j z^{2+j} *
// gamma_j. At m == 1 every formula collapses to the single-value case.
//------------------------------------------------------------------------------

std::size_t
RangeProof::roundsAggregated(std::uint8_t bits, std::uint8_t numValues)
{
    return log2ceil(padTo(bits) * static_cast<std::size_t>(numValues));
}

std::size_t
RangeProof::serializedSizeAggregated(std::uint8_t bits, std::uint8_t numValues)
{
    // No width byte: A,S,T1,T2 + tauX,mu,tHat + 2k IPA points + a,b.
    return 4 * kPointSize + 3 * kScalarSize +
        2 * roundsAggregated(bits, numValues) * kPointSize + 2 * kScalarSize;
}

std::pair<RangeProof, std::vector<PedersenCommitment>>
RangeProof::proveAggregated(
    std::vector<std::uint64_t> const& values,
    std::vector<Scalar> const& blinds,
    std::uint8_t bits,
    Slice const& contextId)
{
    if (bits == 0 || bits > kMaxBits)
        Throw<std::runtime_error>(
            "RangeProof::proveAggregated: invalid bit width");
    std::size_t const m = values.size();
    if (m == 0 || m > 255 || blinds.size() != m || (m & (m - 1)) != 0)
        Throw<std::runtime_error>(
            "RangeProof::proveAggregated: value count must be a non-zero power "
            "of two matching the blind count");

    std::size_t const block = padTo(bits);  // padded per-value width
    std::size_t const n = block * m;         // total (power-of-two) width

    std::vector<PedersenCommitment> commitments;
    commitments.reserve(m);
    for (std::size_t j = 0; j < m; ++j)
        commitments.push_back(PedersenCommitment::commit(values[j], blinds[j]));

    Gens const gen = makeGens(n);
    ECPoint const H = ECPoint::generatorH();
    Scalar const one(std::uint64_t{1});

    // aL = concatenation of each value's bit vector (padding bits stay zero, so
    // each value is bounded by 2^bits rather than 2^block); aR = aL - 1.
    std::vector<Scalar> aL(n), aR(n);
    for (std::size_t j = 0; j < m; ++j)
        for (std::size_t i = 0; i < block; ++i)
        {
            std::size_t const idx = j * block + i;
            std::uint64_t const bit = (i < bits) ? ((values[j] >> i) & 1u) : 0u;
            aL[idx] = Scalar(bit);
            aR[idx] = aL[idx] - one;
        }

    std::vector<Scalar> sL(n), sR(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        sL[i] = Scalar::random();
        sR[i] = Scalar::random();
    }
    Scalar const alpha = Scalar::random();
    Scalar const rho = Scalar::random();

    RangeProof proof;
    proof.bits_ = bits;
    proof.values_ = static_cast<std::uint8_t>(m);
    proof.a_ = msm(aL, gen.g) + msm(aR, gen.h) + ECPoint::mul(alpha, H);
    proof.s_ = msm(sL, gen.g) + msm(sR, gen.h) + ECPoint::mul(rho, H);

    // Transcript: V_0..V_{m-1} || A || S [|| context_id]  ->  challenges y, z.
    std::vector<std::uint8_t> t;
    for (auto const& c : commitments)
        absorb(t, c.point());
    absorb(t, proof.a_);
    absorb(t, proof.s_);
    if (contextId.size())
        t.insert(t.end(), contextId.data(), contextId.data() + contextId.size());
    Slice const tSlice0{t.data(), t.size()};
    Scalar const y = hashToScalar(rpDomain(), {tSlice0, lit("y")});
    Scalar const z = hashToScalar(rpDomain(), {tSlice0, lit("z")});

    // Global y^i across the full width; a single-block 2^k table (reset per
    // block, zero in padding); per-block z power zBlock[j] = z^{2+j}.
    std::vector<Scalar> yPow(n);
    yPow[0] = one;
    for (std::size_t i = 1; i < n; ++i)
        yPow[i] = yPow[i - 1] * y;
    Scalar const two(std::uint64_t{2});
    std::vector<Scalar> twoPowBlock(block);
    twoPowBlock[0] = one;
    for (std::size_t i = 1; i < bits; ++i)
        twoPowBlock[i] = twoPowBlock[i - 1] * two;
    Scalar const z2 = z * z;
    std::vector<Scalar> zBlock(m);
    zBlock[0] = z2;
    for (std::size_t j = 1; j < m; ++j)
        zBlock[j] = zBlock[j - 1] * z;

    // l(X) = (aL - z*1) + sL*X ; r(X) = y o (aR + z*1 + sR*X) + z^{2+j} 2^k.
    std::vector<Scalar> l0(n), l1(n), r0(n), r1(n);
    for (std::size_t j = 0; j < m; ++j)
        for (std::size_t i = 0; i < block; ++i)
        {
            std::size_t const idx = j * block + i;
            l0[idx] = aL[idx] - z;
            l1[idx] = sL[idx];
            r0[idx] = yPow[idx] * (aR[idx] + z) + zBlock[j] * twoPowBlock[i];
            r1[idx] = yPow[idx] * sR[idx];
        }

    Scalar const t1c = inner(l0, r1) + inner(l1, r0);
    Scalar const t2c = inner(l1, r1);
    Scalar const tau1 = Scalar::random();
    Scalar const tau2 = Scalar::random();
    proof.t1_ = PedersenCommitment::commit(t1c, tau1).point();
    proof.t2_ = PedersenCommitment::commit(t2c, tau2).point();

    absorb(t, proof.t1_);
    absorb(t, proof.t2_);
    Slice const tSlice1{t.data(), t.size()};
    Scalar const x = hashToScalar(rpDomain(), {tSlice1, lit("x")});

    std::vector<Scalar> lv(n), rv(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        lv[i] = l0[i] + l1[i] * x;
        rv[i] = r0[i] + r1[i] * x;
    }
    proof.tHat_ = inner(lv, rv);
    // tauX = sum_j z^{2+j} * gamma_j + tau1*x + tau2*x^2.
    Scalar tauX;
    for (std::size_t j = 0; j < m; ++j)
        tauX = tauX + zBlock[j] * blinds[j];
    proof.tauX_ = tauX + tau1 * x + tau2 * (x * x);
    proof.mu_ = alpha + rho * x;

    // Inner-product argument over (lv, rv), identical to the single-value path.
    auto const yInv = y.invert();
    if (!yInv)
        Throw<std::runtime_error>(
            "RangeProof::proveAggregated: non-invertible y");
    std::vector<ECPoint> gv = gen.g;
    std::vector<ECPoint> hv(n);
    Scalar yInvPow = one;
    for (std::size_t i = 0; i < n; ++i)
    {
        hv[i] = ECPoint::mul(yInvPow, gen.h[i]);
        yInvPow = yInvPow * *yInv;
    }

    absorb(t, proof.tHat_);
    Slice const tSlice2{t.data(), t.size()};
    Scalar const w = hashToScalar(rpDomain(), {tSlice2, lit("w")});
    ECPoint const U = ECPoint::mul(w, gen.u);

    std::vector<Scalar> a = lv;
    std::vector<Scalar> b = rv;
    std::vector<std::uint8_t> tip = t;

    std::size_t cur = n;
    while (cur > 1)
    {
        std::size_t const half = cur / 2;
        std::vector<Scalar> aLo(a.begin(), a.begin() + half);
        std::vector<Scalar> aHi(a.begin() + half, a.begin() + cur);
        std::vector<Scalar> bLo(b.begin(), b.begin() + half);
        std::vector<Scalar> bHi(b.begin() + half, b.begin() + cur);
        std::vector<ECPoint> gLo(gv.begin(), gv.begin() + half);
        std::vector<ECPoint> gHi(gv.begin() + half, gv.begin() + cur);
        std::vector<ECPoint> hLo(hv.begin(), hv.begin() + half);
        std::vector<ECPoint> hHi(hv.begin() + half, hv.begin() + cur);

        Scalar const cL = inner(aLo, bHi);
        Scalar const cR = inner(aHi, bLo);
        ECPoint const L = msm(aLo, gHi) + msm(bHi, hLo) + ECPoint::mul(cL, U);
        ECPoint const R = msm(aHi, gLo) + msm(bLo, hHi) + ECPoint::mul(cR, U);
        proof.ipL_.push_back(L);
        proof.ipR_.push_back(R);

        absorb(tip, L);
        absorb(tip, R);
        Scalar const u = hashToScalar(
            rpDomain(), {Slice{tip.data(), tip.size()}, lit("u")});
        auto const uInv = u.invert();
        if (!uInv)
            Throw<std::runtime_error>(
                "RangeProof::proveAggregated: non-invertible u");

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
        cur = half;
    }

    proof.ipa_ = a[0];
    proof.ipb_ = b[0];
    return {proof, commitments};
}

bool
RangeProof::verifyAggregated(
    std::vector<PedersenCommitment> const& commitments,
    Slice const& contextId) const
{
    if (bits_ == 0 || bits_ > kMaxBits)
        return false;
    std::size_t const m = commitments.size();
    if (m == 0 || m != values_ || (m & (m - 1)) != 0)
        return false;
    std::size_t const block = padTo(bits_);
    std::size_t const n = block * m;
    std::size_t const k = log2ceil(n);
    if (ipL_.size() != k || ipR_.size() != k)
        return false;

    Gens const gen = makeGens(n);
    ECPoint const H = ECPoint::generatorH();
    Scalar const one(std::uint64_t{1});

    // Recompute y, z, x from V_0..V_{m-1} || A || S [|| context_id] || T1 || T2.
    std::vector<std::uint8_t> t;
    for (auto const& c : commitments)
        absorb(t, c.point());
    absorb(t, a_);
    absorb(t, s_);
    if (contextId.size())
        t.insert(t.end(), contextId.data(), contextId.data() + contextId.size());
    Slice const tSlice0{t.data(), t.size()};
    Scalar const y = hashToScalar(rpDomain(), {tSlice0, lit("y")});
    Scalar const z = hashToScalar(rpDomain(), {tSlice0, lit("z")});

    absorb(t, t1_);
    absorb(t, t2_);
    Slice const tSlice1{t.data(), t.size()};
    Scalar const x = hashToScalar(rpDomain(), {tSlice1, lit("x")});

    std::vector<Scalar> yPow(n);
    yPow[0] = one;
    for (std::size_t i = 1; i < n; ++i)
        yPow[i] = yPow[i - 1] * y;
    Scalar const two(std::uint64_t{2});
    std::vector<Scalar> twoPowBlock(block);
    twoPowBlock[0] = one;
    for (std::size_t i = 1; i < bits_; ++i)
        twoPowBlock[i] = twoPowBlock[i - 1] * two;
    Scalar const z2 = z * z;
    std::vector<Scalar> zBlock(m);
    zBlock[0] = z2;
    for (std::size_t j = 1; j < m; ++j)
        zBlock[j] = zBlock[j - 1] * z;

    // sum_i y^i (full width) and sum_k 2^k (one block's meaningful bits).
    Scalar sumY;
    for (std::size_t i = 0; i < n; ++i)
        sumY = sumY + yPow[i];
    Scalar sumTwoBlock;
    for (std::size_t i = 0; i < bits_; ++i)
        sumTwoBlock = sumTwoBlock + twoPowBlock[i];

    // delta(y,z) = (z - z^2) sum y^i - sum_j z^{3+j} <1, 2^bits>.
    Scalar delta = (z - z2) * sumY;
    for (std::size_t j = 0; j < m; ++j)
        delta = delta - (zBlock[j] * z) * sumTwoBlock;

    // t-poly opening: tHat*G + tauX*H == sum_j z^{2+j} V_j + delta*G + x T1 +
    // x^2 T2.
    ECPoint const lhsT = ECPoint::mulBase(tHat_) + ECPoint::mul(tauX_, H);
    ECPoint rhsT = ECPoint::mulBase(delta) + ECPoint::mul(x, t1_) +
        ECPoint::mul(x * x, t2_);
    for (std::size_t j = 0; j < m; ++j)
        rhsT = rhsT + ECPoint::mul(zBlock[j], commitments[j].point());
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

    absorb(t, tHat_);
    Slice const tSlice2{t.data(), t.size()};
    Scalar const w = hashToScalar(rpDomain(), {tSlice2, lit("w")});
    ECPoint const U = ECPoint::mul(w, gen.u);

    // P = A + x*S - mu*H + sum_i (-z) g_i + sum_i (z y^i + z^{2+j} 2^k) h'_i +
    //     tHat*U.
    std::vector<Scalar> gExp(n);
    std::vector<Scalar> hExp(n);
    for (std::size_t j = 0; j < m; ++j)
        for (std::size_t i = 0; i < block; ++i)
        {
            std::size_t const idx = j * block + i;
            gExp[idx] = z.negate();
            hExp[idx] = z * yPow[idx] + zBlock[j] * twoPowBlock[i];
        }
    ECPoint P = a_ + ECPoint::mul(x, s_) + ECPoint::mul(mu_.negate(), H) +
        msm(gExp, gv) + msm(hExp, hv) + ECPoint::mul(tHat_, U);

    // Replay IPA rounds (identical to the single-value verifier).
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

    std::vector<Scalar> sVec(n);
    for (std::size_t i = 0; i < n; ++i)
    {
        Scalar prod = one;
        for (std::size_t j = 0; j < k; ++j)
        {
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
        Scalar const sInv = sVec[i].invert().value_or(Scalar());
        hStar = hStar + ECPoint::mul(sInv, hv[i]);
    }

    ECPoint Pfold = P;
    for (std::size_t r = 0; r < k; ++r)
    {
        Scalar const u2 = uChal[r] * uChal[r];
        Scalar const u2Inv = uInvChal[r] * uInvChal[r];
        Pfold = Pfold + ECPoint::mul(u2, ipL_[r]) + ECPoint::mul(u2Inv, ipR_[r]);
    }

    ECPoint const rhs = ECPoint::mul(ipa_, gStar) +
        ECPoint::mul(ipb_, hStar) + ECPoint::mul(ipa_ * ipb_, U);
    return Pfold == rhs;
}

std::vector<std::uint8_t>
RangeProof::serializeAggregated() const
{
    std::vector<std::uint8_t> out;
    out.reserve(serializedSizeAggregated(bits_, values_));
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
RangeProof::deserializeAggregated(
    Slice const& in,
    std::uint8_t bits,
    std::uint8_t numValues)
{
    if (bits == 0 || bits > kMaxBits || numValues == 0 ||
        (numValues & (numValues - 1)) != 0)
        return std::nullopt;
    if (in.size() != serializedSizeAggregated(bits, numValues))
        return std::nullopt;

    RangeProof proof;
    proof.bits_ = bits;
    proof.values_ = numValues;
    std::size_t off = 0;

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

    std::size_t const k = roundsAggregated(bits, numValues);
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
    PedersenCommitment const& commitment,
    Slice const& contextId)
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
    std::vector<Slice> parts{
        Slice{yb.data(), yb.size()},
        Slice{c1b.data(), c1b.size()},
        Slice{c2b.data(), c2b.size()},
        Slice{pb.data(), pb.size()},
        Slice{t1b.data(), t1b.size()},
        Slice{t2b.data(), t2b.size()},
        Slice{t3b.data(), t3b.size()}};
    if (contextId.size())
        parts.push_back(contextId);
    Scalar const e = hashToScalar(lit("XLS96-MPT/link/v1"), parts);

    Scalar const zx = a + e * secret;
    Scalar const zm = b + e * m;
    Scalar const zr = d + e * blind;
    return LinkageProof{e, zx, zm, zr};
}

bool
LinkageProof::verify(
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& ct,
    PedersenCommitment const& commitment,
    Slice const& contextId) const
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
    std::vector<Slice> parts{
        Slice{yb.data(), yb.size()},
        Slice{c1b.data(), c1b.size()},
        Slice{c2b.data(), c2b.size()},
        Slice{pb.data(), pb.size()},
        Slice{t1b.data(), t1b.size()},
        Slice{t2b.data(), t2b.size()},
        Slice{t3b.data(), t3b.size()}};
    if (contextId.size())
        parts.push_back(contextId);
    Scalar const e = hashToScalar(lit("XLS96-MPT/link/v1"), parts);
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
    ElGamalCiphertext const& ct2,
    Slice const& contextId)
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
    std::vector<Slice> parts{
        Slice{y1b.data(), y1b.size()},
        Slice{y2b.data(), y2b.size()},
        Slice{c1a.data(), c1a.size()},
        Slice{c1b.data(), c1b.size()},
        Slice{c2a.data(), c2a.size()},
        Slice{c2b.data(), c2b.size()},
        Slice{a1b.data(), a1b.size()},
        Slice{a2b.data(), a2b.size()},
        Slice{b1b.data(), b1b.size()},
        Slice{b2b.data(), b2b.size()}};
    if (contextId.size())
        parts.push_back(contextId);
    Scalar const e = hashToScalar(lit("XLS96-MPT/pteq/v1"), parts);

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
    ElGamalCiphertext const& ct2,
    Slice const& contextId) const
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
    std::vector<Slice> parts{
        Slice{y1b.data(), y1b.size()},
        Slice{y2b.data(), y2b.size()},
        Slice{c1a.data(), c1a.size()},
        Slice{c1b.data(), c1b.size()},
        Slice{c2a.data(), c2a.size()},
        Slice{c2b.data(), c2b.size()},
        Slice{a1b.data(), a1b.size()},
        Slice{a2b.data(), a2b.size()},
        Slice{b1b.data(), b1b.size()},
        Slice{b2b.data(), b2b.size()}};
    if (contextId.size())
        parts.push_back(contextId);
    Scalar const e = hashToScalar(lit("XLS96-MPT/pteq/v1"), parts);
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
// CompactClawbackProof (mpt-crypto proof_compact_clawback.c)
//------------------------------------------------------------------------------

namespace {

// SHA-256 Fiat-Shamir challenge for the compact AND-composed sigma proofs,
// matching mpt-crypto byte-for-byte: e = reduce32(SHA256(domain || parts ||
// context_id)). The reference hashes with SHA-256 (not SHA-512 like the
// generic hashToScalar), so byte-for-byte interop requires SHA-256 here. The
// 32-byte contextId is appended only when non-empty (the reference's optional
// context_id; an empty Slice matches a NULL context_id and appends nothing).
Scalar
compactChallenge(
    Slice const& domain,
    std::vector<Slice> const& parts,
    Slice const& contextId)
{
    OpensslSha256Hasher h;
    h(domain.data(), domain.size());
    for (auto const& p : parts)
        h(p.data(), p.size());
    if (contextId.size())
        h(contextId.data(), contextId.size());
    auto const digest = OpensslSha256Hasher::result_type(h);
    return Scalar(Slice{digest.data(), digest.size()});
}

Slice
domainClawback()
{
    return lit("CMPT_CLAWBACK_SIGMA");
}

}  // namespace

CompactClawbackProof
CompactClawbackProof::prove(
    Scalar const& secret,
    std::uint64_t amount,
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& issuerMirror,
    Slice const& contextId)
{
    if (secret.isZero() || pub.isInfinity())
        Throw<std::runtime_error>(
            "CompactClawbackProof::prove: identity/zero public key");

    // Witness randomness for Fiat-Shamir.
    Scalar const w = Scalar::random();

    // Commitment points T1, T2.
    ECPoint const T1 = ECPoint::mulBase(w);  // w*G
    ECPoint const mG = ECPoint::mulBase(Scalar(amount));
    ECPoint const diff = issuerMirror.c2() - mG;  // C2 - m*G
    ECPoint const T2 = ECPoint::mul(w, issuerMirror.c1());  // w*C1

    // Fiat-Shamir challenge e = H(domain || P_iss || C1 || C2 || m*G || T1 || T2).
    auto const pb = pub.serialize();
    auto const c1b = issuerMirror.c1().serialize();
    auto const c2b = issuerMirror.c2().serialize();
    auto const mgb = mG.serialize();
    auto const t1b = T1.serialize();
    auto const t2b = T2.serialize();
    Scalar const e = compactChallenge(
        domainClawback(),
        {Slice{pb.data(), pb.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{mgb.data(), mgb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()}},
        contextId);

    // Response: z_sk = w + e*secret.
    Scalar const zsk = w + e * secret;
    return CompactClawbackProof{e, zsk};
}

bool
CompactClawbackProof::verify(
    std::uint64_t amount,
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& issuerMirror,
    Slice const& contextId) const
{
    if (pub.isInfinity())
        return false;

    // Reconstruct commitments:
    // T1 = z_sk*G - e*P_iss
    // T2 = z_sk*C1 - e*(C2 - m*G)
    ECPoint const mG = ECPoint::mulBase(Scalar(amount));
    ECPoint const diff = issuerMirror.c2() - mG;

    ECPoint const T1 = ECPoint::mulBase(zsk_) - ECPoint::mul(e_, pub);
    ECPoint const T2 =
        ECPoint::mul(zsk_, issuerMirror.c1()) - ECPoint::mul(e_, diff);

    // Recompute challenge.
    auto const pb = pub.serialize();
    auto const c1b = issuerMirror.c1().serialize();
    auto const c2b = issuerMirror.c2().serialize();
    auto const mgb = mG.serialize();
    auto const t1b = T1.serialize();
    auto const t2b = T2.serialize();
    Scalar const e = compactChallenge(
        domainClawback(),
        {Slice{pb.data(), pb.size()},
         Slice{c1b.data(), c1b.size()},
         Slice{c2b.data(), c2b.size()},
         Slice{mgb.data(), mgb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()}},
        contextId);
    return e == e_;
}

std::array<std::uint8_t, CompactClawbackProof::kSize>
CompactClawbackProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, zsk_.bytes().data(), kScalarSize);
    return out;
}

std::optional<CompactClawbackProof>
CompactClawbackProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const zsk{Slice{in.data() + kScalarSize, kScalarSize}};
    return CompactClawbackProof{e, zsk};
}

//------------------------------------------------------------------------------
// CompactConvertBackProof (mpt-crypto proof_compact_convertback.c)
//------------------------------------------------------------------------------

namespace {

Slice
domainConvertBack()
{
    return lit("CMPT_CONVERTBACK_SIGMA");
}

}  // namespace

CompactConvertBackProof
CompactConvertBackProof::prove(
    Scalar const& secret,
    std::uint64_t balance,
    Scalar const& rho,
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& postDebit,
    PedersenCommitment const& balanceCommit,
    Slice const& contextId)
{
    if (secret.isZero() || pub.isInfinity())
        Throw<std::runtime_error>(
            "CompactConvertBackProof::prove: identity/zero public key");

    ECPoint const H = ECPoint::generatorH();
    Scalar const b(balance);

    // Witness randomness for Fiat-Shamir.
    Scalar const w_sk = Scalar::random();
    Scalar const w_b = Scalar::random();
    Scalar const w_rho = Scalar::random();

    // Commitments:
    // T_sk1 = w_sk*G
    // T_sk2 = w_b*G + w_sk*B1
    // T_b   = w_b*G + w_rho*H
    ECPoint const T_sk1 = ECPoint::mulBase(w_sk);
    ECPoint const T_sk2 =
        ECPoint::mulBase(w_b) + ECPoint::mul(w_sk, postDebit.c1());
    ECPoint const T_b = ECPoint::mulBase(w_b) + ECPoint::mul(w_rho, H);

    // Fiat-Shamir challenge e = H(domain || P_A || B1 || B2 || PC_b || T_sk1 || T_sk2 || T_b).
    auto const pkb = pub.serialize();
    auto const b1b = postDebit.c1().serialize();
    auto const b2b = postDebit.c2().serialize();
    auto const pcb = balanceCommit.serialize();
    auto const t1b = T_sk1.serialize();
    auto const t2b = T_sk2.serialize();
    auto const tbb = T_b.serialize();
    Scalar const e = compactChallenge(
        domainConvertBack(),
        {Slice{pkb.data(), pkb.size()},
         Slice{b1b.data(), b1b.size()},
         Slice{b2b.data(), b2b.size()},
         Slice{pcb.data(), pcb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()},
         Slice{tbb.data(), tbb.size()}},
        contextId);

    // Responses:
    // z_sk  = w_sk  + e*secret
    // z_b   = w_b   + e*balance
    // z_rho = w_rho + e*rho
    Scalar const z_sk = w_sk + e * secret;
    Scalar const z_b = w_b + e * b;
    Scalar const z_rho = w_rho + e * rho;
    return CompactConvertBackProof{e, z_b, z_rho, z_sk};
}

bool
CompactConvertBackProof::verify(
    ElGamalPublicKey const& pub,
    ElGamalCiphertext const& postDebit,
    PedersenCommitment const& balanceCommit,
    Slice const& contextId) const
{
    if (pub.isInfinity())
        return false;

    ECPoint const H = ECPoint::generatorH();

    // Reconstruct commitments:
    // T_sk1 = z_sk*G - e*P_A
    // T_sk2 = z_b*G + z_sk*B1 - e*B2
    // T_b   = z_b*G + z_rho*H - e*PC_b
    ECPoint const T_sk1 = ECPoint::mulBase(zsk_) - ECPoint::mul(e_, pub);
    ECPoint const T_sk2 = ECPoint::mulBase(zb_) +
        ECPoint::mul(zsk_, postDebit.c1()) - ECPoint::mul(e_, postDebit.c2());
    ECPoint const T_b = ECPoint::mulBase(zb_) + ECPoint::mul(zrho_, H) -
        ECPoint::mul(e_, balanceCommit.point());

    // Recompute challenge.
    auto const pkb = pub.serialize();
    auto const b1b = postDebit.c1().serialize();
    auto const b2b = postDebit.c2().serialize();
    auto const pcb = balanceCommit.serialize();
    auto const t1b = T_sk1.serialize();
    auto const t2b = T_sk2.serialize();
    auto const tbb = T_b.serialize();
    Scalar const e = compactChallenge(
        domainConvertBack(),
        {Slice{pkb.data(), pkb.size()},
         Slice{b1b.data(), b1b.size()},
         Slice{b2b.data(), b2b.size()},
         Slice{pcb.data(), pcb.size()},
         Slice{t1b.data(), t1b.size()},
         Slice{t2b.data(), t2b.size()},
         Slice{tbb.data(), tbb.size()}},
        contextId);
    return e == e_;
}

std::array<std::uint8_t, CompactConvertBackProof::kSize>
CompactConvertBackProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, zb_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 2 * kScalarSize, zrho_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 3 * kScalarSize, zsk_.bytes().data(), kScalarSize);
    return out;
}

std::optional<CompactConvertBackProof>
CompactConvertBackProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const zb{Slice{in.data() + kScalarSize, kScalarSize}};
    Scalar const zrho{Slice{in.data() + 2 * kScalarSize, kScalarSize}};
    Scalar const zsk{Slice{in.data() + 3 * kScalarSize, kScalarSize}};
    return CompactConvertBackProof{e, zb, zrho, zsk};
}

//------------------------------------------------------------------------------
// CompactStandardProof (mpt-crypto proof_compact_standard.c)
//------------------------------------------------------------------------------

namespace {

Slice
domainStandard()
{
    return lit("CMPT_SEND_SIGMA");
}

// Fiat-Shamir challenge for the compact standard send proof. `pts` lists the
// statement points followed by the first-round commitments, in the exact order
// the reference compute_compact_std_challenge() serializes them:
//   pk_1..pk_n, pk_A, C1, C_{2,1}..C_{2,n}, PC_m, PC_b, B1, B2,
//   T1, T_{2,1}..T_{2,n}, T_m, T_b, T_sk1, T_sk2
// so the SHA-256 challenge matches mpt-crypto byte-for-byte and the two
// implementations cross-verify.
Scalar
standardChallenge(std::vector<ECPoint> const& pts, Slice const& contextId)
{
    std::vector<std::array<std::uint8_t, kPointSize>> ser;
    ser.reserve(pts.size());
    for (auto const& p : pts)
        ser.push_back(p.serialize());
    std::vector<Slice> parts;
    parts.reserve(ser.size());
    for (auto const& s : ser)
        parts.push_back(Slice{s.data(), s.size()});
    return compactChallenge(domainStandard(), parts, contextId);
}

// Build the ordered challenge point list shared by prove() and verify(): the
// statement (recipient keys, sender key, shared C1, mirror C2 values, amount
// and balance commitments, balance ciphertext) followed by the six first-round
// commitments.
std::vector<ECPoint>
standardPoints(
    std::vector<ElGamalPublicKey> const& recipientKeys,
    std::vector<ElGamalCiphertext> const& recipientCts,
    ECPoint const& C1,
    PedersenCommitment const& amountCommit,
    ElGamalPublicKey const& senderKey,
    ElGamalCiphertext const& postDebit,
    PedersenCommitment const& balanceCommit,
    ECPoint const& T1,
    std::vector<ECPoint> const& T2,
    ECPoint const& T_m,
    ECPoint const& T_b,
    ECPoint const& T_sk1,
    ECPoint const& T_sk2)
{
    std::size_t const n = recipientKeys.size();
    std::vector<ECPoint> pts;
    pts.reserve(4 + 3 * n + 6);
    for (auto const& pk : recipientKeys)
        pts.push_back(pk);
    pts.push_back(senderKey);
    pts.push_back(C1);
    for (auto const& ct : recipientCts)
        pts.push_back(ct.c2());
    pts.push_back(amountCommit.point());
    pts.push_back(balanceCommit.point());
    pts.push_back(postDebit.c1());
    pts.push_back(postDebit.c2());
    pts.push_back(T1);
    for (auto const& t : T2)
        pts.push_back(t);
    pts.push_back(T_m);
    pts.push_back(T_b);
    pts.push_back(T_sk1);
    pts.push_back(T_sk2);
    return pts;
}

}  // namespace

CompactStandardProof
CompactStandardProof::prove(
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
    Slice const& contextId)
{
    std::size_t const n = recipientKeys.size();
    if (n == 0 || recipientCts.size() != n)
        Throw<std::runtime_error>(
            "CompactStandardProof::prove: empty or mismatched recipients");
    if (secret.isZero() || senderKey.isInfinity())
        Throw<std::runtime_error>(
            "CompactStandardProof::prove: identity/zero sender key");

    // Every recipient mirror must share the single ElGamal nonce C1 = r*G.
    ECPoint const C1 = recipientCts[0].c1();
    for (std::size_t i = 0; i < n; ++i)
    {
        if (recipientKeys[i].isInfinity())
            Throw<std::runtime_error>(
                "CompactStandardProof::prove: identity recipient key");
        if (recipientCts[i].c1() != C1)
            Throw<std::runtime_error>(
                "CompactStandardProof::prove: non-shared ciphertext nonce");
    }

    ECPoint const H = ECPoint::generatorH();
    ECPoint const& B1 = postDebit.c1();
    Scalar const m(amount);
    Scalar const b(balance);

    // Nonces: w_r (r), w_m (m), w_sk (sk_A), w_rho (rho), w_b (b).
    Scalar const w_r = Scalar::random();
    Scalar const w_m = Scalar::random();
    Scalar const w_sk = Scalar::random();
    Scalar const w_rho = Scalar::random();
    Scalar const w_b = Scalar::random();

    // First-round commitments (mirror the reference exactly):
    //   T1     = w_r*G
    //   T2_i   = w_r*pk_i + w_m*G
    //   T_m    = w_m*G + w_r*H
    //   T_sk1  = w_sk*G
    //   T_b    = w_b*G + w_rho*H
    //   T_sk2  = w_sk*B1 + w_b*G
    ECPoint const T1 = ECPoint::mulBase(w_r);
    std::vector<ECPoint> T2(n);
    for (std::size_t i = 0; i < n; ++i)
        T2[i] = ECPoint::mul(w_r, recipientKeys[i]) + ECPoint::mulBase(w_m);
    ECPoint const T_m = ECPoint::mulBase(w_m) + ECPoint::mul(w_r, H);
    ECPoint const T_sk1 = ECPoint::mulBase(w_sk);
    ECPoint const T_b = ECPoint::mulBase(w_b) + ECPoint::mul(w_rho, H);
    ECPoint const T_sk2 = ECPoint::mul(w_sk, B1) + ECPoint::mulBase(w_b);

    Scalar const e = standardChallenge(
        standardPoints(
            recipientKeys,
            recipientCts,
            C1,
            amountCommit,
            senderKey,
            postDebit,
            balanceCommit,
            T1,
            T2,
            T_m,
            T_b,
            T_sk1,
            T_sk2),
        contextId);

    // Responses: z = w + e*witness.
    Scalar const z_m = w_m + e * m;
    Scalar const z_r = w_r + e * rShared;
    Scalar const z_b = w_b + e * b;
    Scalar const z_rho = w_rho + e * rho;
    Scalar const z_sk = w_sk + e * secret;
    return CompactStandardProof{e, z_m, z_r, z_b, z_rho, z_sk};
}

bool
CompactStandardProof::verify(
    std::vector<ElGamalPublicKey> const& recipientKeys,
    std::vector<ElGamalCiphertext> const& recipientCts,
    PedersenCommitment const& amountCommit,
    ElGamalPublicKey const& senderKey,
    ElGamalCiphertext const& postDebit,
    PedersenCommitment const& balanceCommit,
    Slice const& contextId) const
{
    std::size_t const n = recipientKeys.size();
    if (n == 0 || recipientCts.size() != n || senderKey.isInfinity())
        return false;

    // Every recipient mirror must share the single ElGamal nonce C1.
    ECPoint const C1 = recipientCts[0].c1();
    for (std::size_t i = 0; i < n; ++i)
    {
        if (recipientKeys[i].isInfinity())
            return false;
        if (recipientCts[i].c1() != C1)
            return false;
    }

    ECPoint const H = ECPoint::generatorH();
    ECPoint const& B1 = postDebit.c1();
    ECPoint const& B2 = postDebit.c2();

    // Reconstruct the first-round commitments:
    //   T1     = z_r*G - e*C1
    //   T2_i   = z_r*pk_i + z_m*G - e*C_{2,i}
    //   T_m    = z_m*G + z_r*H - e*PC_m
    //   T_sk1  = z_sk*G - e*pk_A
    //   T_b    = z_b*G + z_rho*H - e*PC_b
    //   T_sk2  = z_sk*B1 + z_b*G - e*B2
    ECPoint const T1 = ECPoint::mulBase(zr_) - ECPoint::mul(e_, C1);
    std::vector<ECPoint> T2(n);
    for (std::size_t i = 0; i < n; ++i)
        T2[i] = ECPoint::mul(zr_, recipientKeys[i]) + ECPoint::mulBase(zm_) -
            ECPoint::mul(e_, recipientCts[i].c2());
    ECPoint const T_m = ECPoint::mulBase(zm_) + ECPoint::mul(zr_, H) -
        ECPoint::mul(e_, amountCommit.point());
    ECPoint const T_sk1 = ECPoint::mulBase(zsk_) - ECPoint::mul(e_, senderKey);
    ECPoint const T_b = ECPoint::mulBase(zb_) + ECPoint::mul(zrho_, H) -
        ECPoint::mul(e_, balanceCommit.point());
    ECPoint const T_sk2 = ECPoint::mul(zsk_, B1) + ECPoint::mulBase(zb_) -
        ECPoint::mul(e_, B2);

    Scalar const e = standardChallenge(
        standardPoints(
            recipientKeys,
            recipientCts,
            C1,
            amountCommit,
            senderKey,
            postDebit,
            balanceCommit,
            T1,
            T2,
            T_m,
            T_b,
            T_sk1,
            T_sk2),
        contextId);
    return e == e_;
}

std::array<std::uint8_t, CompactStandardProof::kSize>
CompactStandardProof::serialize() const
{
    std::array<std::uint8_t, kSize> out{};
    std::memcpy(out.data(), e_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + kScalarSize, zm_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 2 * kScalarSize, zr_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 3 * kScalarSize, zb_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 4 * kScalarSize, zrho_.bytes().data(), kScalarSize);
    std::memcpy(out.data() + 5 * kScalarSize, zsk_.bytes().data(), kScalarSize);
    return out;
}

std::optional<CompactStandardProof>
CompactStandardProof::deserialize(Slice const& in)
{
    if (in.size() != kSize)
        return std::nullopt;
    Scalar const e{Slice{in.data(), kScalarSize}};
    Scalar const zm{Slice{in.data() + kScalarSize, kScalarSize}};
    Scalar const zr{Slice{in.data() + 2 * kScalarSize, kScalarSize}};
    Scalar const zb{Slice{in.data() + 3 * kScalarSize, kScalarSize}};
    Scalar const zrho{Slice{in.data() + 4 * kScalarSize, kScalarSize}};
    Scalar const zsk{Slice{in.data() + 5 * kScalarSize, kScalarSize}};
    return CompactStandardProof{e, zm, zr, zb, zrho, zsk};
}

//------------------------------------------------------------------------------

namespace {

account_id
toAccountId(AccountID const& a)
{
    account_id out{};
    static_assert(sizeof(out.bytes) == AccountID::size());
    std::memcpy(out.bytes, a.data(), sizeof(out.bytes));
    return out;
}

mpt_issuance_id
toIssuanceId(MPTID const& id)
{
    mpt_issuance_id out{};
    static_assert(sizeof(out.bytes) == MPTID::size());
    std::memcpy(out.bytes, id.data(), sizeof(out.bytes));
    return out;
}

}  // namespace

std::array<std::uint8_t, kContextIdSize>
clawbackContextId(
    AccountID const& issuer,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    AccountID const& holder)
{
    std::array<std::uint8_t, kContextIdSize> out{};
    if (mpt_get_clawback_context_hash(
            toAccountId(issuer),
            toIssuanceId(issuanceId),
            sequence,
            toAccountId(holder),
            out.data()) != 0)
        Throw<std::runtime_error>("clawbackContextId: derivation failed");
    return out;
}

std::array<std::uint8_t, kContextIdSize>
convertBackContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    std::uint32_t version)
{
    std::array<std::uint8_t, kContextIdSize> out{};
    if (mpt_get_convert_back_context_hash(
            toAccountId(account),
            toIssuanceId(issuanceId),
            sequence,
            version,
            out.data()) != 0)
        Throw<std::runtime_error>("convertBackContextId: derivation failed");
    return out;
}

std::array<std::uint8_t, kContextIdSize>
convertContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence)
{
    std::array<std::uint8_t, kContextIdSize> out{};
    if (mpt_get_convert_context_hash(
            toAccountId(account),
            toIssuanceId(issuanceId),
            sequence,
            out.data()) != 0)
        Throw<std::runtime_error>("convertContextId: derivation failed");
    return out;
}

std::array<std::uint8_t, kContextIdSize>
sendContextId(
    AccountID const& account,
    MPTID const& issuanceId,
    std::uint32_t sequence,
    AccountID const& dest,
    std::uint32_t version)
{
    std::array<std::uint8_t, kContextIdSize> out{};
    if (mpt_get_send_context_hash(
            toAccountId(account),
            toIssuanceId(issuanceId),
            sequence,
            toAccountId(dest),
            version,
            out.data()) != 0)
        Throw<std::runtime_error>("sendContextId: derivation failed");
    return out;
}

}  // namespace cmpt
}  // namespace xrpl
