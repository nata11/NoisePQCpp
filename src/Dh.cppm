//
// Copyright 2024-2026 Nadeem Ahmed
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// For research citation guidance, see RESEARCH-CITATION.md.
//

module;

#include "botan_all.h"

export module noise:dh;

import :common;
import :errors;

export namespace Noise
{
    using PrivateKey = std::vector<std::uint8_t>;  ///< Raw private key bytes.
    using PublicKey = std::vector<std::uint8_t>;    ///< Raw public key bytes.

    /** Aggregate holding a private/public key pair for DH or KEM algorithms. */
    struct KeyPair {
        PrivateKey private_key = {};  ///< Raw private key (scalar for DH, decapsulation key for KEM).
        PublicKey public_key = {};    ///< Raw public key (point for DH, encapsulation key for KEM).

        /** @return True if both keys are empty (no key material loaded). */
        [[nodiscard]] bool IsEmpty() const {
            return private_key.empty() && public_key.empty();
        }
    };

    class Dh;

    /**
     * A loaded DH private key (X25519 or X448), owned by the caller and usable for many DH()
     * calls (Noise spec Section 4.1).
     *
     * Botan derives the public key when it loads a raw scalar, which costs one full scalar
     * multiplication, the same as the agreement itself. Loading the key once and reusing the
     * handle for every DH token of a handshake halves the per-token cost. HandshakeState does
     * this for its ephemeral and static keys; applications can do the same for a long-lived
     * static key through Dh::LoadPrivateKey.
     *
     * Move-only, and constructible only by Dh (Dh::LoadPrivateKey, Dh::GenerateKeypairWithKey).
     * It exposes no key bytes; Botan zeroizes the key data when the last owner is destroyed.
     */
    class DhPrivateKey {
    public:
        DhPrivateKey(const DhPrivateKey&) = delete;
        DhPrivateKey& operator=(const DhPrivateKey&) = delete;
        DhPrivateKey(DhPrivateKey&&) noexcept = default;
        DhPrivateKey& operator=(DhPrivateKey&&) noexcept = default;
        ~DhPrivateKey() = default;

        /** @return The DH algorithm this key belongs to (KeyAlgo::X25519 or KeyAlgo::X448). */
        [[nodiscard]] KeyAlgo Algorithm() const noexcept {
            return m_algo;
        }

    private:
        friend class Dh;

        DhPrivateKey(std::unique_ptr<Botan::PK_Key_Agreement> agree, const KeyAlgo algo) noexcept
            : m_agree{std::move(agree)}, m_algo{algo} {}

        std::unique_ptr<Botan::PK_Key_Agreement> m_agree;  ///< Botan "Raw" key agreement over the loaded key.
        KeyAlgo m_algo;                                    ///< Algorithm of the loaded key.
    };

    /**
     * A loaded ML-KEM public (encapsulation) key, owned by the caller and usable for many
     * Encapsulate() calls (FIPS 203 Encaps).
     *
     * Decoding an encapsulation key performs the FIPS 203 Section 7.2 modulus check and expands
     * the key's matrix from its seed, which is most of an encapsulation's cost for the small
     * message sizes Noise uses. Dh::LoadPublicKey does that once and keeps the decoded key, so
     * each later Encapsulate(handle) spends no decode. HandshakeState loads every ML-KEM key it
     * receives (e, s, e1) this way at the ReadMessage that carries it, which is also where the
     * key is checked; applications that encapsulate to a known server key repeatedly can load it
     * once.
     *
     * Move-only, and constructible only by Dh (Dh::LoadPublicKey). It exposes no Botan type. A
     * public key is not secret, so nothing is scrubbed when the handle is destroyed.
     */
    class KemPublicKey {
    public:
        KemPublicKey(const KemPublicKey&) = delete;
        KemPublicKey& operator=(const KemPublicKey&) = delete;
        KemPublicKey(KemPublicKey&&) noexcept = default;
        KemPublicKey& operator=(KemPublicKey&&) noexcept = default;
        ~KemPublicKey() = default;

        /** @return The KEM this key belongs to (KeyAlgo::M512, KeyAlgo::M768 or KeyAlgo::M1024). */
        [[nodiscard]] KeyAlgo Algorithm() const noexcept {
            return m_algo;
        }

    private:
        friend class Dh;

        KemPublicKey(std::unique_ptr<Botan::ML_KEM_PublicKey> key, const KeyAlgo algo) noexcept
            : m_key{std::move(key)}, m_algo{algo} {}

        std::unique_ptr<Botan::ML_KEM_PublicKey> m_key;  ///< The decoded encapsulation key.
        KeyAlgo m_algo;                                  ///< Algorithm of the loaded key.
    };

    /**
     * Unified DH and KEM key exchange interface (Noise spec Section 4.1).
     *
     * Provides a single interface for both classical Diffie-Hellman (X25519, X448)
     * and post-quantum KEM (ML-KEM-512/768/1024, per FIPS 203). Higher layers use
     * IsKEM() to select between DH() for classical key agreement and
     * Encapsulate()/Decapsulate() for KEM operations.
     *
     * Shared secrets are 32 bytes (56 for X448); SymmetricState::MixKey() takes either
     * length, so DH and KEM outputs are processed uniformly.
     *
     * @see Noise spec Section 4.1 (DH functions)
     * @see FIPS 203 (ML-KEM / CRYSTALS-Kyber)
     * @see RFC 7748 (X25519 / X448)
     */
    class Dh {
    public:
        /** Default constructor: X25519. */
        Dh() : Dh{KeyAlgo::X25519} {}

        /**
         * Construct from a KeyAlgo enum value. The value is checked against KeyAlgos first.
         * @param algo One of the five Noise DH/KEM algorithms.
         * @throws ProtocolNotSupportedError If algo is not an entry of KeyAlgos.
         */
        explicit Dh(const KeyAlgo algo) : m_algo{Validate(algo)} {
            // Everything a call needs is fixed here, so no operation compares strings.
            switch (m_algo) {
            case KeyAlgo::X25519:
                m_dhLen = 32;
                m_publicKeySize = 32;
                break;
            case KeyAlgo::X448:
                m_dhLen = 56;
                m_publicKeySize = 56;
                break;
            case KeyAlgo::M512:
                m_dhLen = 32;  // Shared secret size for all ML-KEM variants
                m_publicKeySize = M512_PUBLIC_KEY_SIZE;
                m_ciphertextSize = M512_CIPHERTEXT_SIZE;
                m_mlkemMode = Botan::ML_KEM_Mode::ML_KEM_512;
                break;
            case KeyAlgo::M768:
                m_dhLen = 32;
                m_publicKeySize = M768_PUBLIC_KEY_SIZE;
                m_ciphertextSize = M768_CIPHERTEXT_SIZE;
                m_mlkemMode = Botan::ML_KEM_Mode::ML_KEM_768;
                break;
            case KeyAlgo::M1024:
                m_dhLen = 32;
                m_publicKeySize = M1024_PUBLIC_KEY_SIZE;
                m_ciphertextSize = M1024_CIPHERTEXT_SIZE;
                m_mlkemMode = Botan::ML_KEM_Mode::ML_KEM_1024;
                break;
            }
            m_kem_mode = m_mlkemMode.has_value();
        }

        /**
         * Construct from an algorithm name string.
         *
         * Supported names: "25519" (X25519), "448" (X448), "M512" (ML-KEM-512),
         * "M768" (ML-KEM-768), "M1024" (ML-KEM-1024). The name is resolved through KeyAlgos,
         * then the enum constructor runs.
         *
         * @param algo_name Algorithm identifier string.
         * @throws ProtocolNotSupportedError If the algorithm name is not recognized.
         */
        explicit Dh(const std::string_view algo_name) : Dh{Resolve(algo_name)} {}

        Dh(const Dh& other) = default;
        Dh(Dh&& other) noexcept = default;
        Dh& operator=(const Dh&) = delete;
        Dh& operator=(Dh&&) = delete;

        /** @return The shared secret size in bytes (32, or 56 for X448). */
        [[nodiscard]] std::uint8_t Size() const {
            return m_dhLen;
        }

        /**
         * @return The public key size in bytes.
         *
         * For DH: equals Size() (32 for X25519, 56 for X448).
         * For KEM: returns the encapsulation key size per FIPS 203 Table 3
         * (800 for ML-KEM-512, 1184 for ML-KEM-768, 1568 for ML-KEM-1024).
         */
        [[nodiscard]] std::size_t PublicKeySize() const {
            return m_publicKeySize;
        }

        /**
         * @return The KEM ciphertext size in bytes (FIPS 203 Table 3).
         * @throws NoiseError If called on a DH algorithm (not KEM).
         */
        [[nodiscard]] std::size_t CiphertextSize() const {
            if (!m_kem_mode) {
                throw NoiseError("CiphertextSize() only valid for KEM algorithms.");
            }
            return m_ciphertextSize;
        }

        /** @return True if this is a KEM algorithm (ML-KEM), false for DH (X25519/X448). */
        [[nodiscard]] bool IsKEM() const {
            return m_kem_mode;
        }

        /**
         * Generates a fresh keypair using the system CSPRNG (Botan::System_RNG).
         *
         * For DH: generates a random scalar and derives the public point.
         * For KEM: generates a decapsulation/encapsulation key pair per FIPS 203; the
         * private key is Botan's default seed format (64 bytes, d || z).
         *
         * The key object is built directly for the algorithm fixed at construction (no
         * name-based factory dispatch); the raw encodings are the same as before.
         *
         * @return KeyPair with raw private and public key bytes.
         * @throws NoiseError If the key generation backend fails.
         */
        [[nodiscard]] KeyPair GenerateKeypair() const {
            try {
                Botan::System_RNG rng;

                const auto make = [](const Botan::Private_Key& sk) {
                    const auto priv_bits = sk.raw_private_key_bits();
                    const auto pub_bits = sk.raw_public_key_bits();
                    return KeyPair{
                        .private_key = {priv_bits.begin(), priv_bits.end()},
                        .public_key = {pub_bits.begin(), pub_bits.end()}
                    };
                };

                switch (m_algo) {
                case KeyAlgo::X25519: return make(Botan::X25519_PrivateKey{rng});
                case KeyAlgo::X448:   return make(Botan::X448_PrivateKey{rng});
                default:              return make(Botan::ML_KEM_PrivateKey{rng, GetMLKEMMode()});
                }
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/GenerateKeypair: ") + e.what());
            }
        }

        /**
         * Validates a peer public key for this algorithm without keeping any key object.
         *
         * For DH (X25519, X448) only the length is checked: a low-order point is detected
         * by DH(), which rejects it with InvalidPublicKeyError (Noise spec Section 4.1
         * allows the error at DH time). For ML-KEM the length is checked and the
         * encapsulation key is decoded, which performs the FIPS 203 Section 7.2 modulus
         * check on every coefficient.
         *
         * HandshakeState performs the same checks on every ML-KEM key it receives (e, s, e1)
         * before the key is stored, passed to the observer, or mixed into the handshake hash,
         * through LoadPublicKey, which keeps the decoded key for the encapsulation that follows.
         *
         * @param key The raw public key bytes to validate.
         * @throws InvalidPublicKeyError If the length is wrong for the algorithm, or an
         *         ML-KEM key fails the FIPS 203 check.
         */
        void ValidatePublicKey(const std::span<const std::uint8_t> key) const {
            if (key.size() != PublicKeySize()) [[unlikely]] {
                throw InvalidPublicKeyError{};
            }

            if (!m_kem_mode) {
                return;
            }

            // The same decode as LoadPublicKey; the object itself is not kept.
            (void)LoadPublicKey(key);
        }

        /**
         * Loads a peer ML-KEM encapsulation key into a reusable key object (KEM algorithms only).
         *
         * Performs exactly ValidatePublicKey's checks, the length and the FIPS 203 Section 7.2
         * decode, and keeps the decoded key instead of discarding it, so Encapsulate(handle)
         * spends no second decode. HandshakeState loads each received ML-KEM key this way at the
         * ReadMessage that carries it.
         *
         * @param peer_public_key The remote party's raw ML-KEM encapsulation key.
         * @return A move-only handle for Encapsulate(const KemPublicKey&).
         * @throws InvalidPublicKeyError If peer_public_key has the wrong length for the
         *         algorithm, or fails the FIPS 203 Section 7.2 encapsulation-key check.
         * @throws NoiseError If called on a DH algorithm.
         */
        [[nodiscard]] KemPublicKey LoadPublicKey(const std::span<const std::uint8_t> peer_public_key) const {
            RequireKem("LoadPublicKey");

            if (peer_public_key.size() != PublicKeySize()) [[unlikely]] {
                throw InvalidPublicKeyError{};
            }

            try {
                // The decoder rejects any coefficient >= q (FIPS 203 Section 7.2)
                return KemPublicKey{std::make_unique<Botan::ML_KEM_PublicKey>(peer_public_key, GetMLKEMMode()), m_algo};
            }
            catch (const Botan::Exception&) {
                throw InvalidPublicKeyError{};
            }
        }

        /**
         * Loads a raw DH private key into a reusable key object (DH algorithms only).
         *
         * Botan derives the public key while loading the scalar, which is one full scalar
         * multiplication. The returned handle keeps the loaded key, so each later
         * DH(handle, peer) costs one multiplication instead of two. HandshakeState loads
         * its static key this way at the first static DH token.
         *
         * @param my_raw_priv Raw private scalar (32 bytes for X25519, 56 for X448).
         * @return A move-only handle for DH(const DhPrivateKey&, peer).
         * @throws NoiseError If called on a KEM algorithm, if my_raw_priv has the wrong
         *         length, or if the key backend fails for any other reason.
         */
        [[nodiscard]] DhPrivateKey LoadPrivateKey(const std::span<const std::uint8_t> my_raw_priv) const {
            RequireDh("LoadPrivateKey");

            // A wrong private-key length is a caller error, not a peer error.
            if (my_raw_priv.size() != Size()) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh/LoadPrivateKey: private key size");
            }

            try {
                Botan::System_RNG rng;

                if (m_algo == KeyAlgo::X25519) {
                    const Botan::X25519_PrivateKey sk(my_raw_priv);   // derives the public key: one multiplication
                    return MakeHandle(sk, rng);
                }
                const Botan::X448_PrivateKey sk(my_raw_priv);
                return MakeHandle(sk, rng);
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/LoadPrivateKey: ") + e.what());
            }
        }

        /**
         * Generates a fresh DH keypair together with its loaded key object (DH algorithms only).
         *
         * The public key is derived once, at generation, and the handle is built from the same
         * key object, so no second multiplication is spent on loading. HandshakeState uses this
         * for the ephemeral key it generates at the 'e' token.
         *
         * @return The raw KeyPair (as GenerateKeypair()) and the handle for the same key.
         * @throws NoiseError If called on a KEM algorithm, or if the key generation backend fails.
         */
        [[nodiscard]] std::pair<KeyPair, DhPrivateKey> GenerateKeypairWithKey() const {
            RequireDh("GenerateKeypairWithKey");

            try {
                Botan::System_RNG rng;

                const auto make = [&](const Botan::Private_Key& sk) {
                    const auto priv_bits = sk.raw_private_key_bits();
                    const auto pub_bits = sk.raw_public_key_bits();   // computed by the constructor, read here

                    return std::pair<KeyPair, DhPrivateKey>{
                        KeyPair{
                            .private_key = {priv_bits.begin(), priv_bits.end()},
                            .public_key = {pub_bits.begin(), pub_bits.end()}
                        },
                        MakeHandle(sk, rng)};
                };

                if (m_algo == KeyAlgo::X25519) {
                    return make(Botan::X25519_PrivateKey{rng});
                }
                return make(Botan::X448_PrivateKey{rng});
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/GenerateKeypairWithKey: ") + e.what());
            }
        }

        /**
         * Performs classical Diffie-Hellman key agreement with a loaded key (Noise spec
         * Section 4.1 DH): one scalar multiplication.
         *
         * @param my_key A handle from LoadPrivateKey() or GenerateKeypairWithKey() of a Dh with
         *        the same algorithm.
         * @param peer_raw_pub Remote public key (raw u-coordinate bytes).
         * @return The shared secret (32 bytes for X25519, 56 for X448).
         * @throws InvalidPublicKeyError If peer_raw_pub has the wrong length for the
         *         algorithm, or is a low-order point (the shared secret would be all zeros,
         *         RFC 7748 Section 6).
         * @throws NoiseError If called on a KEM algorithm, if my_key belongs to another
         *         algorithm, or if the key agreement backend fails for any other reason.
         */
        [[nodiscard]] std::vector<std::uint8_t> DH(
            const DhPrivateKey& my_key,
            const std::span<const std::uint8_t> peer_raw_pub) const
        {
            RequireDh("DH");

            // A key of another algorithm is a caller error, not a peer error: check it first
            // so that it is never reported as an invalid public key.
            if (my_key.m_algo != m_algo) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh/DH: key algorithm mismatch");
            }

            if (peer_raw_pub.size() != PublicKeySize()) [[unlikely]] {
                throw InvalidPublicKeyError{};
            }

            Botan::secure_vector<std::uint8_t> ss;
            try {
                ss = my_key.m_agree->derive_key(m_dhLen, peer_raw_pub).bits_of();
            }
            catch (const Botan::Invalid_Argument&) {
                // With the length already checked, derive_key() rejects exactly the low-order
                // peer points (an all-zero shared secret, RFC 7748 Section 6).
                throw InvalidPublicKeyError{};
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/DH: ") + e.what());
            }
            return {ss.begin(), ss.end()};
        }

        /**
         * Performs classical Diffie-Hellman key agreement (Noise spec Section 4.1 DH).
         *
         * Computes the raw shared secret: my_private * peer_public on the curve.
         * Only valid for DH algorithms (X25519, X448). Loads the scalar (one multiplication)
         * and agrees (another); callers that reuse a key should load it once with
         * LoadPrivateKey() and call DH(const DhPrivateKey&, peer).
         *
         * @param my_raw_priv Local private key (raw scalar bytes).
         * @param peer_raw_pub Remote public key (raw u-coordinate bytes).
         * @return The shared secret (32 bytes for X25519, 56 for X448).
         * @throws InvalidPublicKeyError If peer_raw_pub has the wrong length for the
         *         algorithm, or is a low-order point (the shared secret would be all zeros,
         *         RFC 7748 Section 6).
         * @throws NoiseError If called on a KEM algorithm, if my_raw_priv has the wrong
         *         length, or if the key agreement backend fails for any other reason.
         */
        [[nodiscard]] inline std::vector<std::uint8_t> DH(
            const std::span<const std::uint8_t> my_raw_priv,
            const std::span<const std::uint8_t> peer_raw_pub) const
        {
            if (m_kem_mode) {
                throw NoiseError("DH() not supported for KEM algorithms. Use Encapsulate()/Decapsulate() instead.");
            }

            // A wrong private-key length is a caller error, not a peer error: check it first
            // so that it is never reported as an invalid public key.
            if (my_raw_priv.size() != Size()) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh/DH: private key size");
            }

            if (peer_raw_pub.size() != PublicKeySize()) [[unlikely]] {
                throw InvalidPublicKeyError{};
            }

            return DH(LoadPrivateKey(my_raw_priv), peer_raw_pub);
        }

        /** Convenience overload accepting KeyPair structs. */
        [[nodiscard]] inline std::vector<std::uint8_t> DH(const KeyPair& me, const KeyPair& peer) const {
            return DH(me.private_key, peer.public_key);
        }

        /**
         * KEM encapsulation to a loaded key: generates a shared secret and ciphertext
         * (FIPS 203 Encaps) without decoding the key again.
         *
         * @param peer_public_key A handle from LoadPublicKey() of a Dh with the same algorithm.
         * @return Pair of {ciphertext, shared_secret} (each as byte vectors).
         * @throws NoiseError If called on a DH algorithm, if the handle belongs to another
         *         algorithm, or if the encapsulation backend fails for any other reason.
         */
        [[nodiscard]] std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
        Encapsulate(const KemPublicKey& peer_public_key) const {
            RequireKem("Encapsulate");

            // A key of another algorithm is a caller error, not a peer error: check it first
            // so that it is never reported as an invalid public key.
            if (peer_public_key.m_algo != m_algo) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh/Encapsulate: key algorithm mismatch");
            }

            try {
                Botan::System_RNG rng;

                // Create encryptor over the loaded key and perform encapsulation
                Botan::PK_KEM_Encryptor encryptor(*peer_public_key.m_key, "Raw");
                const auto kem_result = encryptor.encrypt(rng, m_dhLen);

                // Extract encapsulated key and shared secret
                return {
                    std::vector<std::uint8_t>(kem_result.encapsulated_shared_key().begin(),
                                              kem_result.encapsulated_shared_key().end()),
                    std::vector<std::uint8_t>(kem_result.shared_key().begin(),
                                              kem_result.shared_key().end())
                };
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/Encapsulate: ") + e.what());
            }
        }

        /**
         * KEM encapsulation: generates a shared secret and ciphertext (FIPS 203 Encaps).
         *
         * Encapsulates to the peer's public (encapsulation) key, producing a ciphertext
         * that only the holder of the corresponding private key can decapsulate. Decodes the
         * key (LoadPublicKey) and encapsulates to it; callers that encapsulate to the same key
         * more than once should load it once and call Encapsulate(const KemPublicKey&).
         *
         * @param peer_public_key The remote party's ML-KEM encapsulation key.
         * @return Pair of {ciphertext, shared_secret} (each as byte vectors).
         * @throws InvalidPublicKeyError If peer_public_key has the wrong length or fails the
         *         FIPS 203 Section 7.2 encapsulation-key check.
         * @throws NoiseError If called on a DH algorithm, or if the encapsulation backend
         *         fails for any other reason.
         */
        [[nodiscard]] std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
        Encapsulate(const std::span<const std::uint8_t> peer_public_key) const {
            if (!m_kem_mode) {
                throw NoiseError("Encapsulate() only supported for KEM algorithms (M512, M768, M1024)");
            }
            return Encapsulate(LoadPublicKey(peer_public_key));
        }

        /**
         * KEM decapsulation: recovers the shared secret from a ciphertext (FIPS 203 Decaps).
         *
         * Uses the local private (decapsulation) key to recover the shared secret.
         * ML-KEM provides IND-CCA2 security with implicit rejection — if the
         * ciphertext is invalid, a pseudorandom value is returned instead of failing,
         * preventing chosen-ciphertext attacks.
         *
         * @param my_private_key Local ML-KEM decapsulation key.
         * @param encapsulated_key The ciphertext from the peer's Encapsulate() call.
         * @return The 32-byte shared secret.
         * @throws NoiseError If called on a DH algorithm, if encapsulated_key has the wrong
         *         length (CiphertextSize()), if my_private_key does not decode, or if the
         *         decapsulation backend fails for any other reason.
         */
        [[nodiscard]] std::vector<std::uint8_t>
        Decapsulate(const std::span<const std::uint8_t> my_private_key,
                    const std::span<const std::uint8_t> encapsulated_key) const {
            if (!m_kem_mode) {
                throw NoiseError("Decapsulate() only supported for KEM algorithms (M512, M768, M1024)");
            }

            if (encapsulated_key.size() != CiphertextSize()) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh/Decapsulate: ciphertext size");
            }

            try {
                Botan::System_RNG rng;

                // Reconstruct private key from bytes
                const Botan::ML_KEM_PrivateKey priv_key(my_private_key, GetMLKEMMode());

                // Create decryptor and perform decapsulation
                Botan::PK_KEM_Decryptor decryptor(priv_key, rng, "Raw");

                // Decrypt using the proper API (returns secure_vector)
                const auto shared_secret = decryptor.decrypt(encapsulated_key.data(),
                                                             encapsulated_key.size(),
                                                             m_dhLen);

                return {shared_secret.begin(), shared_secret.end()};
            }
            catch (const Botan::Exception& e) {
                // Botan types never escape the library (NoiseError model)
                throw NoiseError(std::string("noisepqc++/Dh/Decapsulate: ") + e.what());
            }
        }

        void PrintKeys(const KeyPair& keypair) const {
            std::println("Algorithm: {}", String());

            std::print("Private Key: ");
            for (const auto byte : keypair.private_key) {
                std::print("{:02x}", byte);
            }
            std::println("");

            std::print("Public Key: ");
            for (const auto byte : keypair.public_key) {
                std::print("{:02x}", byte);
            }
            std::println("");
        }

        [[nodiscard]] std::string_view String() const {
            return GetKeyAlgorithmName(m_algo);
        }

    private:
        /** @throws NoiseError If this is a KEM algorithm (the DH-only entry points). */
        void RequireDh(const std::string_view where) const {
            if (m_kem_mode) [[unlikely]] {
                throw NoiseError(std::string("noisepqc++/Dh/") + std::string(where) +
                                 ": DH algorithms only (X25519, X448); use Encapsulate()/Decapsulate() for ML-KEM");
            }
        }

        /** @throws NoiseError If this is a DH algorithm (the KEM-only entry points). */
        void RequireKem(const std::string_view where) const {
            if (!m_kem_mode) [[unlikely]] {
                throw NoiseError(std::string("noisepqc++/Dh/") + std::string(where) +
                                 ": KEM algorithms only (M512, M768, M1024); use DH() for X25519/X448");
            }
        }

        /** Wraps a loaded Botan key in a "Raw" key agreement handle; the operation keeps its own
         *  shared reference to the key data, so the key object itself need not outlive it. */
        [[nodiscard]] DhPrivateKey MakeHandle(const Botan::Private_Key& sk, Botan::RandomNumberGenerator& rng) const {
            return DhPrivateKey{std::make_unique<Botan::PK_Key_Agreement>(sk, rng, "Raw"), m_algo};
        }

        /** Resolves a Noise DH/KEM name through the Common table or throws ProtocolNotSupportedError. */
        static KeyAlgo Resolve(const std::string_view algo_name) {
            const auto algo = ParseKeyAlgo(algo_name);
            if (!algo) {
                throw ProtocolNotSupportedError{};
            }
            return *algo;
        }

        /** Returns algo if KeyAlgos lists it, else throws ProtocolNotSupportedError. */
        static KeyAlgo Validate(const KeyAlgo algo) {
            if (!std::ranges::any_of(KeyAlgos, [algo](const auto& entry) { return entry.first == algo; })) {
                throw ProtocolNotSupportedError{};
            }
            return algo;
        }

        /** Botan's ML_KEM_Mode for this KEM, fixed at construction. */
        [[nodiscard]] Botan::ML_KEM_Mode GetMLKEMMode() const {
            if (!m_mlkemMode) [[unlikely]] {
                throw NoiseError("noisepqc++/Dh: not an ML-KEM algorithm");
            }
            return *m_mlkemMode;
        }

        const KeyAlgo m_algo;
        std::uint8_t m_dhLen = 0;                     ///< Shared secret size (and DH key size).
        std::size_t m_publicKeySize = 0;              ///< Public key size for the algorithm.
        std::size_t m_ciphertextSize = 0;             ///< KEM ciphertext size (0 for DH).
        std::optional<Botan::ML_KEM_Mode> m_mlkemMode; ///< Set for the three ML-KEM levels.
        bool m_kem_mode = false;
    };
}