#include <xrpl/basics/Slice.h>
#include <xrpl/beast/unit_test/suite.h>
#include <xrpl/protocol/ConfidentialMPT.h>
#include <xrpl/protocol/ECMath.h>

#include <cstdint>
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
    }

    void
    testElGamal();
    void
    testSchnorr();
    void
    testRangeProof();
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
}

void
ConfidentialMPT_test::testRangeProof()
{
    testcase("Bit-decomposition range proof");

    std::uint8_t const bits = 16;
    Scalar const blind = Scalar::random();
    std::uint64_t const value = 12345;  // < 2^16

    auto const [proof, commitment] = RangeProof::prove(value, blind, bits);
    BEAST_EXPECT(proof.verify(commitment));

    // The proof is bound to its commitment: a different commitment fails.
    auto const otherCommit =
        PedersenCommitment::commit(value + 1, blind);
    BEAST_EXPECT(!proof.verify(otherCommit));

    // Serialization round-trip still verifies.
    auto const sb = proof.serialize();
    auto const back = RangeProof::deserialize(Slice{sb.data(), sb.size()});
    BEAST_EXPECT(back.has_value() && back->verify(commitment));

    // Tampering with a response scalar breaks verification.
    auto tampered = sb;
    tampered[1 + cmpt::kPointSize] ^= 0x01;  // first challenge byte of bit 0
    auto const bad = RangeProof::deserialize(Slice{tampered.data(), tampered.size()});
    BEAST_EXPECT(bad.has_value() && !bad->verify(commitment));

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
}

BEAST_DEFINE_TESTSUITE(ConfidentialMPT, protocol, xrpl);

}  // namespace xrpl
