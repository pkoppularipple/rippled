#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <optional>
#include <vector>

namespace xrpl {

class ConfidentialMPT_test : public beast::unit_test::Suite
{
    using Scalar = cmpt::Scalar;
    using ECPoint = cmpt::ECPoint;
    using PedersenCommitment = cmpt::PedersenCommitment;
    using ElGamalSecretKey = cmpt::ElGamalSecretKey;
    using ElGamalCiphertext = cmpt::ElGamalCiphertext;
    using SchnorrProof = cmpt::SchnorrProof;
    using RangeProof = cmpt::RangeProof;
    using LinkageProof = cmpt::LinkageProof;
    using PlaintextEqualityProof = cmpt::PlaintextEqualityProof;

    void
    testScalar()
    {
        testcase("Scalar arithmetic");

        Scalar const zero;
        BEAST_EXPECT(zero.isZero());

        Scalar const a(std::uint64_t{7});
        Scalar const b(std::uint64_t{35});
        BEAST_EXPECT((a + b) == Scalar(std::uint64_t{42}));
        BEAST_EXPECT((b - a) == Scalar(std::uint64_t{28}));
        BEAST_EXPECT((a * b) == Scalar(std::uint64_t{245}));

        // a + (-a) == 0
        BEAST_EXPECT((a + a.negate()).isZero());

        // a * a^-1 == 1
        auto const inv = a.invert();
        BEAST_EXPECT(inv.has_value());
        BEAST_EXPECT((a * *inv) == Scalar(std::uint64_t{1}));

        // zero has no inverse
        BEAST_EXPECT(!zero.invert().has_value());

        // subtraction wraps modulo n (0 - 1 != 0, and adding 1 returns to 0)
        Scalar const negOne = zero - Scalar(std::uint64_t{1});
        BEAST_EXPECT(!negOne.isZero());
        BEAST_EXPECT((negOne + Scalar(std::uint64_t{1})).isZero());
    }

    void
    testPoints()
    {
        testcase("EC point operations and generators");

        ECPoint const inf = ECPoint::infinity();
        BEAST_EXPECT(inf.isInfinity());

        ECPoint const g = ECPoint::base();
        ECPoint const h = ECPoint::generatorH();
        BEAST_EXPECT(!g.isInfinity());
        BEAST_EXPECT(!h.isInfinity());
        // Independent generators.
        BEAST_EXPECT(g != h);
        // H is deterministic.
        BEAST_EXPECT(h == ECPoint::generatorH());

        // Identity behaviour.
        BEAST_EXPECT((g + inf) == g);
        BEAST_EXPECT((g + g.negate()).isInfinity());

        // 2*G == G + G, 3*G == 2*G + G.
        ECPoint const g2 = ECPoint::mulBase(Scalar(std::uint64_t{2}));
        BEAST_EXPECT(g2 == (g + g));
        ECPoint const g3 = ECPoint::mulBase(Scalar(std::uint64_t{3}));
        BEAST_EXPECT(g3 == (g2 + g));

        // Scalar multiplication of a non-base point.
        BEAST_EXPECT(ECPoint::mul(Scalar(std::uint64_t{2}), h) == (h + h));

        // 0*G is the identity.
        BEAST_EXPECT(ECPoint::mulBase(Scalar()).isInfinity());

        // Serialization round-trip.
        auto const sb = g3.serialize();
        auto const back = ECPoint::deserialize(Slice{sb.data(), sb.size()});
        BEAST_EXPECT(back.has_value() && *back == g3);
    }

    void
    testPedersen()
    {
        testcase("Pedersen commitment homomorphism");

        Scalar const r1 = Scalar::random();
        Scalar const r2 = Scalar::random();
        auto const c1 = PedersenCommitment::commit(std::uint64_t{100}, r1);
        auto const c2 = PedersenCommitment::commit(std::uint64_t{55}, r2);

        // commit(v1,r1) + commit(v2,r2) == commit(v1+v2, r1+r2)
        auto const sum = c1 + c2;
        auto const expected =
            PedersenCommitment::commit(std::uint64_t{155}, r1 + r2);
        BEAST_EXPECT(sum == expected);

        // Different blindings give different commitments to the same value.
        auto const other = PedersenCommitment::commit(std::uint64_t{100}, r2);
        BEAST_EXPECT(!(c1 == other));

        // Serialization round-trip.
        auto const sb = c1.serialize();
        auto const back = PedersenCommitment::deserialize(Slice{sb.data(), sb.size()});
        BEAST_EXPECT(back.has_value() && *back == c1);
    }

    void
    run() override
    {
        testScalar();
        testPoints();
        testPedersen();
        testElGamal();
        testSchnorr();
        testRangeProof();
        testLinkageProof();
        testPlaintextEqualityProof();
    }

    void
    testElGamal();
    void
    testSchnorr();
    void
    testRangeProof();
    void
    testLinkageProof();
    void
    testPlaintextEqualityProof();
};

void
ConfidentialMPT_test::testElGamal()
{
    testcase("EC-ElGamal encryption, decryption, homomorphism");

    auto const sk = ElGamalSecretKey::random();
    auto const pk = sk.publicKey();
    BEAST_EXPECT(!pk.isInfinity());

    // Round-trip.
    auto const ct = ElGamalCiphertext::encrypt(pk, 42);
    auto const m = ct.decrypt(sk.x, 1000);
    BEAST_EXPECT(m.has_value() && *m == 42);

    // Additive homomorphism: Enc(7) + Enc(35) decrypts to 42.
    auto const sum = ElGamalCiphertext::encrypt(pk, 7) +
        ElGamalCiphertext::encrypt(pk, 35);
    auto const ms = sum.decrypt(sk.x, 1000);
    BEAST_EXPECT(ms.has_value() && *ms == 42);

    // Canonical zero.
    auto const zero = ElGamalCiphertext::encryptZero();
    auto const mz = zero.decrypt(sk.x, 1000);
    BEAST_EXPECT(mz.has_value() && *mz == 0);

    // A value beyond the search bound is not recovered.
    auto const big = ElGamalCiphertext::encrypt(pk, 5000);
    BEAST_EXPECT(!big.decrypt(sk.x, 1000).has_value());

    // The wrong secret key does not recover the plaintext.
    auto const sk2 = ElGamalSecretKey::random();
    BEAST_EXPECT(ct.decrypt(sk2.x, 1000) != std::optional<std::uint64_t>{42});

    // Encrypting under the identity/all-zero public key is rejected. Such a key
    // removes the k*Y mask, leaving c2 = m*G and making balances recoverable
    // without the secret key. Both overloads route through the same guard.
    ECPoint const idKey = ECPoint::infinity();
    BEAST_EXPECT(idKey.isInfinity());
    {
        bool threw = false;
        try
        {
            ElGamalCiphertext::encrypt(idKey, 1);
        }
        catch (std::exception const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);
    }
    {
        bool threw = false;
        try
        {
            ElGamalCiphertext::encrypt(idKey, 1, Scalar::random());
        }
        catch (std::exception const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);
    }

    // Serialization round-trip.
    auto const sb = ct.serialize();
    auto const back = ElGamalCiphertext::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && *back == ct);
}

void
ConfidentialMPT_test::testSchnorr()
{
    testcase("Schnorr proof of knowledge of secret key");

    auto const sk = ElGamalSecretKey::random();
    auto const pk = sk.publicKey();

    auto const proof = SchnorrProof::prove(sk.x, pk);
    BEAST_EXPECT(proof.verify(pk));

    // A proof does not verify against a different public key.
    auto const sk2 = ElGamalSecretKey::random();
    BEAST_EXPECT(!proof.verify(sk2.publicKey()));

    // Serialization round-trip still verifies.
    auto const sb = proof.serialize();
    auto const back = SchnorrProof::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && back->verify(pk));

    // Tampering with the proof breaks verification.
    auto tampered = sb;
    tampered[0] ^= 0x01;
    auto const bad = SchnorrProof::deserialize(Slice{tampered.data(), tampered.size()});
    BEAST_EXPECT(bad.has_value() && !bad->verify(pk));

    // Rogue-key guard: no proof verifies against the identity/all-zero public
    // key. Otherwise a proof for the zero secret would verify (the e*Y term
    // vanishes at infinity), enabling recovery of EC-ElGamal balances.
    ECPoint const idKey = ECPoint::infinity();
    BEAST_EXPECT(!proof.verify(idKey));

    // A zero-secret forged proof must not verify either. Replicate the classic
    // forgery (s = w, e = H(pub, w*G)) that a naive verifier would accept.
    {
        Scalar const w = Scalar::random();
        ECPoint const t = ECPoint::mulBase(w);
        auto const pb = idKey.serialize();
        auto const tb = t.serialize();
        char const domain[] = "XLS96-MPT/PoK/v1";
        Scalar const e = cmpt::hashToScalar(
            Slice{reinterpret_cast<std::uint8_t const*>(domain), sizeof(domain) - 1},
            {Slice{pb.data(), pb.size()}, Slice{tb.data(), tb.size()}});
        SchnorrProof const forged(e, w);
        BEAST_EXPECT(!forged.verify(idKey));
    }

    // The prover refuses to produce a proof for a zero secret / identity key.
    {
        bool threw = false;
        try
        {
            SchnorrProof::prove(Scalar(), idKey);
        }
        catch (std::exception const&)
        {
            threw = true;
        }
        BEAST_EXPECT(threw);
    }
}

void
ConfidentialMPT_test::testRangeProof()
{
    testcase("Aggregated Bulletproof range proof");

    std::uint8_t const bits = 16;
    Scalar const blind = Scalar::random();
    std::uint64_t const value = 12345;  // < 2^16

    auto const [proof, commitment] = RangeProof::prove(value, blind, bits);
    BEAST_EXPECT(proof.verify(commitment));

    // Logarithmic proof size: serialized length grows with log2(bits), not bits.
    BEAST_EXPECT(proof.serialize().size() == RangeProof::serializedSize(bits));

    // The proof is bound to its commitment: a different commitment fails.
    auto const otherCommit =
        PedersenCommitment::commit(value + 1, blind);
    BEAST_EXPECT(!proof.verify(otherCommit));

    // Serialization round-trip still verifies.
    auto const sb = proof.serialize();
    auto const back = RangeProof::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && back->verify(commitment));

    // Tampering with the tauX scalar (first scalar after A, S, T1, T2) breaks
    // verification.
    auto tampered = sb;
    tampered[1 + 4 * cmpt::kPointSize] ^= 0x01;
    auto const bad = RangeProof::deserialize(Slice{tampered.data(), tampered.size()});
    BEAST_EXPECT(bad.has_value() && !bad->verify(commitment));

    // Tampering with the folded inner-product scalar a (last but one scalar)
    // also breaks verification.
    auto tampered2 = sb;
    tampered2[sb.size() - 1] ^= 0x01;  // last byte of ipb
    auto const bad2 = RangeProof::deserialize(Slice{tampered2.data(), tampered2.size()});
    BEAST_EXPECT(bad2.has_value() && !bad2->verify(commitment));

    // A value outside [0, 2^bits) cannot produce a verifying proof.
    auto const [badProof, badCommit] =
        RangeProof::prove(70000, blind, bits);  // 70000 > 2^16
    BEAST_EXPECT(!badProof.verify(badCommit));

    // Edge values 0 and 2^bits - 1 verify.
    {
        Scalar const r0 = Scalar::random();
        auto const [p0, c0] = RangeProof::prove(0, r0, bits);
        BEAST_EXPECT(p0.verify(c0));
        Scalar const rm = Scalar::random();
        auto const [pm, cm] = RangeProof::prove(65535, rm, bits);
        BEAST_EXPECT(pm.verify(cm));
    }

    // Full 64-bit width: boundaries 0 and 2^64 - 1 verify and round-trip.
    {
        std::uint8_t const w = 64;
        Scalar const r0 = Scalar::random();
        auto const [p0, c0] = RangeProof::prove(0, r0, w);
        BEAST_EXPECT(p0.verify(c0));

        Scalar const rmax = Scalar::random();
        std::uint64_t const vmax = ~std::uint64_t{0};  // 2^64 - 1
        auto const [pm, cm] = RangeProof::prove(vmax, rmax, w);
        BEAST_EXPECT(pm.verify(cm));

        auto const sb64 = pm.serialize();
        BEAST_EXPECT(sb64.size() == RangeProof::serializedSize(w));
        auto const back64 = RangeProof::deserialize(Slice{sb64.data(), sb64.size()});
        BEAST_EXPECT(back64.has_value() && back64->verify(cm));
    }

    // Non-power-of-two width (padded internally) still round-trips and verifies.
    {
        std::uint8_t const w = 32;
        Scalar const r = Scalar::random();
        auto const [p, c] = RangeProof::prove(0xdeadbeef, r, w);
        BEAST_EXPECT(p.verify(c));
        auto const blob = p.serialize();
        auto const back = RangeProof::deserialize(Slice{blob.data(), blob.size()});
        BEAST_EXPECT(back.has_value() && back->verify(c));
    }

    // Soundness: padding positions must contribute nothing to the represented
    // value. A proof generated at width 64 for a value with bit 63 set is
    // honest at width 64, but relabelling it as a 63-bit proof (which also pads
    // to 64) must NOT verify -- otherwise a malicious 63-bit balance proof
    // could commit to value + 2^63 and defeat the post-debit non-negativity
    // bound that relies on width 63.
    {
        Scalar const r = Scalar::random();
        std::uint64_t const v = (std::uint64_t{1} << 63) | 0x1234u;  // >= 2^63
        auto const [p64, c64] = RangeProof::prove(v, r, 64);
        BEAST_EXPECT(p64.verify(c64));  // honest at width 64

        // Forge by relabelling as a 63-bit proof. padTo(63) == padTo(64) == 64,
        // so the serialized length is identical and the blob deserializes.
        auto blob = p64.serialize();
        BEAST_EXPECT(blob.size() == RangeProof::serializedSize(63));
        blob[0] = 63;  // leading bit-width byte
        auto const forged = RangeProof::deserialize(Slice{blob.data(), blob.size()});
        BEAST_EXPECT(forged.has_value() && forged->bits() == 63);
        // Must reject: padded top bit no longer contributes to the value.
        BEAST_EXPECT(forged.has_value() && !forged->verify(c64));
    }

    // Honest proof at a padded (non-power-of-two) width 63 still verifies, so
    // the soundness fix does not break valid proofs at that width.
    {
        Scalar const r = Scalar::random();
        std::uint64_t const v = (std::uint64_t{1} << 62) + 7;  // < 2^63
        auto const [p, c] = RangeProof::prove(v, r, 63);
        BEAST_EXPECT(p.verify(c));
        auto const blob = p.serialize();
        auto const back = RangeProof::deserialize(Slice{blob.data(), blob.size()});
        BEAST_EXPECT(back.has_value() && back->verify(c));
    }

    // Aggregated (multi-value) Bulletproof: two 63-bit values proven together,
    // as used by ConfidentialMPTSend (amount + post-debit balance).
    {
        std::uint8_t const w = 63;
        Scalar const ra = Scalar::random();
        Scalar const rb = Scalar::random();
        std::uint64_t const amount = 400;
        std::uint64_t const balance = 600;
        auto const [agg, commits] =
            RangeProof::proveAggregated({amount, balance}, {ra, rb}, w);
        BEAST_EXPECT(commits.size() == 2);
        BEAST_EXPECT(agg.values() == 2);
        BEAST_EXPECT(agg.verifyAggregated(commits));

        // The commitments are the plain Pedersen commitments of each value.
        BEAST_EXPECT(commits[0] == PedersenCommitment::commit(amount, ra));
        BEAST_EXPECT(commits[1] == PedersenCommitment::commit(balance, rb));

        // Aggregation is logarithmic: N = padTo(63) * 2 = 128 -> 7 IPA rounds,
        // and the wire form carries no leading width byte.
        auto const sb = agg.serializeAggregated();
        BEAST_EXPECT(
            sb.size() == RangeProof::serializedSizeAggregated(w, 2));
        BEAST_EXPECT(sb.size() == 754);

        auto const back = RangeProof::deserializeAggregated(
            Slice{sb.data(), sb.size()}, w, 2);
        BEAST_EXPECT(back.has_value() && back->verifyAggregated(commits));

        // Commitment order matters: swapping the two commitments must fail.
        BEAST_EXPECT(!agg.verifyAggregated({commits[1], commits[0]}));

        // A tampered scalar (tauX, first scalar after A, S, T1, T2) breaks it.
        auto tampered = sb;
        tampered[4 * cmpt::kPointSize] ^= 0x01;
        auto const bad = RangeProof::deserializeAggregated(
            Slice{tampered.data(), tampered.size()}, w, 2);
        BEAST_EXPECT(bad.has_value() && !bad->verifyAggregated(commits));

        // Wrong shape on deserialize is rejected (size mismatch).
        BEAST_EXPECT(!RangeProof::deserializeAggregated(
            Slice{sb.data(), sb.size()}, w, 4));
    }

    // Aggregated soundness: any value outside [0, 2^bits) fails to verify.
    {
        std::uint8_t const w = 63;
        Scalar const ra = Scalar::random();
        Scalar const rb = Scalar::random();
        std::uint64_t const ok = 12345;
        std::uint64_t const bad = std::uint64_t{1} << 63;  // >= 2^63
        auto const [agg, commits] =
            RangeProof::proveAggregated({ok, bad}, {ra, rb}, w);
        BEAST_EXPECT(!agg.verifyAggregated(commits));
    }

    // Aggregated with a single value reduces to a valid one-value proof.
    {
        std::uint8_t const w = 32;
        Scalar const r = Scalar::random();
        auto const [agg, commits] =
            RangeProof::proveAggregated({0xdeadbeef}, {r}, w);
        BEAST_EXPECT(commits.size() == 1 && agg.values() == 1);
        BEAST_EXPECT(agg.verifyAggregated(commits));
    }
}

void
ConfidentialMPT_test::testLinkageProof()
{
    testcase("ElGamal-Pedersen linkage proof");

    auto const sk = ElGamalSecretKey::random();
    auto const pk = sk.publicKey();

    std::uint64_t const value = 4242;
    Scalar const k = Scalar::random();    // ciphertext randomness
    Scalar const r = Scalar::random();    // commitment blinding

    auto const ct = ElGamalCiphertext::encrypt(pk, value, k);
    auto const commitment = PedersenCommitment::commit(value, r);

    auto const proof = LinkageProof::prove(sk.x, value, r, ct, commitment);
    BEAST_EXPECT(proof.verify(pk, ct, commitment));

    // Wrong public key fails.
    auto const otherSk = ElGamalSecretKey::random();
    BEAST_EXPECT(!proof.verify(otherSk.publicKey(), ct, commitment));

    // A commitment to a different value fails (the value is no longer linked).
    auto const otherCommit = PedersenCommitment::commit(value + 1, r);
    BEAST_EXPECT(!proof.verify(pk, ct, otherCommit));

    // A ciphertext of a different value fails.
    auto const otherCt = ElGamalCiphertext::encrypt(pk, value + 1, k);
    BEAST_EXPECT(!proof.verify(pk, otherCt, commitment));

    // The identity public key never verifies (rogue-key guard).
    BEAST_EXPECT(!proof.verify(ECPoint::infinity(), ct, commitment));

    // Serialization round-trip preserves verification.
    auto const sb = proof.serialize();
    // Fixed serialized length matches the advertised serializedSize().
    BEAST_EXPECT(sb.size() == LinkageProof::serializedSize());
    auto const back = LinkageProof::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && back->verify(pk, ct, commitment));

    // Tampering with a response scalar breaks verification.
    auto tampered = sb;
    tampered[cmpt::kScalarSize] ^= 0x01;  // first byte of zx
    auto const bad = LinkageProof::deserialize(Slice{tampered.data(), tampered.size()});
    BEAST_EXPECT(bad.has_value() && !bad->verify(pk, ct, commitment));

    // Wrong-size blobs (short and long) fail to deserialize.
    BEAST_EXPECT(!LinkageProof::deserialize(Slice{sb.data(), sb.size() - 1}).has_value());
    {
        std::array<std::uint8_t, LinkageProof::serializedSize() + 1> oversize{};
        std::memcpy(oversize.data(), sb.data(), sb.size());
        BEAST_EXPECT(
            !LinkageProof::deserialize(Slice{oversize.data(), oversize.size()})
                 .has_value());
    }
}

void
ConfidentialMPT_test::testPlaintextEqualityProof()
{
    testcase("Plaintext-equality proof");

    auto const sk1 = ElGamalSecretKey::random();
    auto const sk2 = ElGamalSecretKey::random();
    auto const pk1 = sk1.publicKey();
    auto const pk2 = sk2.publicKey();

    std::uint64_t const value = 999;
    Scalar const k1 = Scalar::random();
    Scalar const k2 = Scalar::random();

    auto const ct1 = ElGamalCiphertext::encrypt(pk1, value, k1);
    auto const ct2 = ElGamalCiphertext::encrypt(pk2, value, k2);

    auto const proof =
        PlaintextEqualityProof::prove(pk1, pk2, value, k1, k2, ct1, ct2);
    BEAST_EXPECT(proof.verify(pk1, pk2, ct1, ct2));

    // Two ciphertexts encrypting different plaintexts must not produce a
    // verifying equality proof.
    auto const ct2bad = ElGamalCiphertext::encrypt(pk2, value + 1, k2);
    auto const badProof =
        PlaintextEqualityProof::prove(pk1, pk2, value, k1, k2, ct1, ct2bad);
    BEAST_EXPECT(!badProof.verify(pk1, pk2, ct1, ct2bad));

    // Swapping the ciphertexts / keys fails.
    BEAST_EXPECT(!proof.verify(pk2, pk1, ct1, ct2));
    BEAST_EXPECT(!proof.verify(pk1, pk2, ct2, ct1));

    // Identity key guard.
    BEAST_EXPECT(!proof.verify(ECPoint::infinity(), pk2, ct1, ct2));

    // Serialization round-trip preserves verification.
    auto const sb = proof.serialize();
    // Fixed serialized length matches the advertised serializedSize().
    BEAST_EXPECT(sb.size() == PlaintextEqualityProof::serializedSize());
    auto const back =
        PlaintextEqualityProof::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && back->verify(pk1, pk2, ct1, ct2));

    // Tampering breaks verification.
    auto tampered = sb;
    tampered[0] ^= 0x01;  // first byte of challenge e
    auto const bad =
        PlaintextEqualityProof::deserialize(Slice{tampered.data(), tampered.size()});
    BEAST_EXPECT(bad.has_value() && !bad->verify(pk1, pk2, ct1, ct2));

    // Wrong-size blobs (short and long) fail to deserialize.
    BEAST_EXPECT(
        !PlaintextEqualityProof::deserialize(Slice{sb.data(), sb.size() - 1}).has_value());
    {
        std::array<std::uint8_t, PlaintextEqualityProof::serializedSize() + 1>
            oversize{};
        std::memcpy(oversize.data(), sb.data(), sb.size());
        BEAST_EXPECT(!PlaintextEqualityProof::deserialize(
                          Slice{oversize.data(), oversize.size()})
                          .has_value());
    }
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, protocol, xrpl);

}  // namespace xrpl
