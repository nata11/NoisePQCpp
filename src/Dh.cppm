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

    /**
     * Unified DH and KEM key exchange interface (Noise spec Section 4.1).
     *
     * Provides a single interface for both classical Diffie-Hellman (X25519, X448)
     * and post-quantum KEM (ML-KEM-512/768/1024, per FIPS 203). Higher layers use
     * IsKEM() to select between DH() for classical key agreement and
     * Encapsulate()/Decapsulate() for KEM operations.
     *
     * All algorithms produce 32-byte shared secrets for uniform downstream processing
     * by SymmetricState::MixKey().
     *
     * @see Noise spec Section 4.1 (DH functions)
     * @see FIPS 203 (ML-KEM / CRYSTALS-Kyber)
     * @see RFC 7748 (X25519 / X448)
     */
    class Dh {
    public:
        /** Default constructor: X25519. */
        Dh() : Dh{"25519"} {}

        /** Construct from a KeyAlgo enum value. */
        explicit Dh(const KeyAlgo algo) : Dh{GetKeyAlgorithmName(algo)} {}

        /**
         * Construct from an algorithm name string.
         *
         * Supported names: "25519" (X25519), "448" (X448), "M512" (ML-KEM-512),
         * "M768" (ML-KEM-768), "M1024" (ML-KEM-1024).
         *
         * @param algo_name Algorithm identifier string.
         * @throws NoiseError If the algorithm name is not recognized.
         */
        explicit Dh(const std::string_view algo_name) : m_algoName{algo_name} {

            if (m_algoName == "25519") {
                m_botan_name = "X25519";;
                m_dhLen = 32;
                m_kem_mode = false;
            }
            else if (m_algoName == "448") {
                m_botan_name = "X448";
                m_dhLen = 56;
                m_kem_mode = false;
            }
            else if (m_algoName == "M512") {
                m_botan_name = "ML-KEM";
                m_dhLen = 32;  // Shared secret size for all ML-KEM variants
                m_kem_level = "ML-KEM-512";
                m_kem_mode = true;
            }
            else if (m_algoName == "M768") {
                m_botan_name = "ML-KEM";
                m_dhLen = 32;  // Shared secret size for all ML-KEM variants
                m_kem_level = "ML-KEM-768";
                m_kem_mode = true;
            }
            else if (m_algoName == "M1024") {
                m_botan_name = "ML-KEM";
                m_dhLen = 32;  // Shared secret size for all ML-KEM variants
                m_kem_level = "ML-KEM-1024";
                m_kem_mode = true;
            }
            else {
                throw NoiseError("Unsupported DH algorithm: " + std::string(m_algoName));
            }
        }

        Dh(const Dh& other) = default;
        Dh(Dh&& other) noexcept = default;
        Dh& operator=(const Dh&) = delete;
        Dh& operator=(Dh&&) = delete;

        /** @return The shared secret size in bytes (32 for all algorithms). */
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
            if (!m_kem_mode) {
                return m_dhLen;
            }

            if (m_kem_level == "ML-KEM-512") return M512_PUBLIC_KEY_SIZE;
            if (m_kem_level == "ML-KEM-768") return M768_PUBLIC_KEY_SIZE;
            if (m_kem_level == "ML-KEM-1024") return M1024_PUBLIC_KEY_SIZE;

            throw NoiseError("Unknown KEM public key size for: " + m_kem_level);
        }

        /**
         * @return The KEM ciphertext size in bytes (FIPS 203 Table 3).
         * @throws NoiseError If called on a DH algorithm (not KEM).
         */
        [[nodiscard]] std::size_t CiphertextSize() const {
            if (!m_kem_mode) {
                throw NoiseError("CiphertextSize() only valid for KEM algorithms.");
            }

            if (m_kem_level == "ML-KEM-512") return M512_CIPHERTEXT_SIZE;
            if (m_kem_level == "ML-KEM-768") return M768_CIPHERTEXT_SIZE;
            if (m_kem_level == "ML-KEM-1024") return M1024_CIPHERTEXT_SIZE;

            throw NoiseError("Unknown KEM ciphertext size for: " + m_kem_level);
        }

        /** @return True if this is a KEM algorithm (ML-KEM), false for DH (X25519/X448). */
        [[nodiscard]] bool IsKEM() const {
            return m_kem_mode;
        }

        /**
         * Generates a fresh keypair using the system CSPRNG (Botan::System_RNG).
         *
         * For DH: generates a random scalar and derives the public point.
         * For KEM: generates a decapsulation/encapsulation key pair per FIPS 203.
         *
         * @return KeyPair with raw private and public key bytes.
         */
        [[nodiscard]] KeyPair GenerateKeypair() const {
            Botan::System_RNG rng;

            const auto priv_key = Botan::create_private_key(m_botan_name, rng, m_kem_level);

            const auto priv_bits = priv_key->raw_private_key_bits();
            const auto pub_bits = priv_key->raw_public_key_bits();

            return KeyPair{
                .private_key = {priv_bits.begin(), priv_bits.end()},
                .public_key = {pub_bits.begin(), pub_bits.end()}
            };
        }

        /**
         * Performs classical Diffie-Hellman key agreement (Noise spec Section 4.1 DH).
         *
         * Computes the raw shared secret: my_private * peer_public on the curve.
         * Only valid for DH algorithms (X25519, X448).
         *
         * @param my_raw_priv Local private key (raw scalar bytes).
         * @param peer_raw_pub Remote public key (raw u-coordinate bytes).
         * @return The shared secret (32 bytes for X25519, 56 for X448).
         * @throws NoiseError If called on a KEM algorithm or key sizes mismatch.
         */
        [[nodiscard]] inline std::vector<std::uint8_t> DH(
            const std::span<const std::uint8_t> my_raw_priv,
            const std::span<const std::uint8_t> peer_raw_pub) const
        {
            if (m_kem_mode) {
                throw NoiseError("DH() not supported for KEM algorithms. Use Encapsulate()/Decapsulate() instead.");
            }

            if (my_raw_priv.size() != peer_raw_pub.size()) {
                throw NoiseError("DH key length mismatch: private and public keys must be the same size");
            }

            Botan::System_RNG rng;

            if (m_botan_name == "X25519") {
                const Botan::X25519_PrivateKey sk(
                    Botan::secure_vector<std::uint8_t>(my_raw_priv.begin(), my_raw_priv.end()));
                const Botan::PK_Key_Agreement ka(sk, rng, "Raw");
                auto ss = ka.derive_key(m_dhLen, peer_raw_pub).bits_of();
                return {ss.begin(), ss.end()};
            }
            else {
                const Botan::X448_PrivateKey sk(
                    Botan::secure_vector<std::uint8_t>(my_raw_priv.begin(), my_raw_priv.end()));
                const Botan::PK_Key_Agreement ka(sk, rng, "Raw");
                auto ss = ka.derive_key(m_dhLen, peer_raw_pub).bits_of();
                return {ss.begin(), ss.end()};
            }
        }

        /** Convenience overload accepting KeyPair structs. */
        [[nodiscard]] inline std::vector<std::uint8_t> DH(const KeyPair& me, const KeyPair& peer) const {
            return DH(
                std::span<const std::uint8_t>(me.private_key.data(), me.private_key.size()),
                std::span<const std::uint8_t>(peer.public_key.data(), peer.public_key.size()));
        }

        /**
         * KEM encapsulation: generates a shared secret and ciphertext (FIPS 203 Encaps).
         *
         * Encapsulates to the peer's public (encapsulation) key, producing a ciphertext
         * that only the holder of the corresponding private key can decapsulate.
         *
         * @param peer_public_key The remote party's ML-KEM encapsulation key.
         * @return Pair of {ciphertext, shared_secret} (each as byte vectors).
         * @throws NoiseError If called on a DH algorithm.
         */
        [[nodiscard]] std::pair<std::vector<std::uint8_t>, std::vector<std::uint8_t>>
        Encapsulate(const std::span<const std::uint8_t> peer_public_key) const {
            if (!m_kem_mode) {
                throw NoiseError("Encapsulate() only supported for KEM algorithms (M512, M768, M1024)");
            }

            Botan::System_RNG rng;

            // Reconstruct public key from bytes
            const Botan::ML_KEM_Mode mode = GetMLKEMMode();
            Botan::ML_KEM_PublicKey pub_key(peer_public_key, mode);

            // Create encryptor and perform encapsulation
            Botan::PK_KEM_Encryptor encryptor(pub_key, "Raw");
            const auto kem_result = encryptor.encrypt(rng, m_dhLen);

            // Extract encapsulated key and shared secret
            return {
                std::vector<std::uint8_t>(kem_result.encapsulated_shared_key().begin(),
                                          kem_result.encapsulated_shared_key().end()),
                std::vector<std::uint8_t>(kem_result.shared_key().begin(),
                                          kem_result.shared_key().end())
            };
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
         * @throws NoiseError If called on a DH algorithm.
         */
        [[nodiscard]] std::vector<std::uint8_t>
        Decapsulate(const std::span<const std::uint8_t> my_private_key,
                    const std::span<const std::uint8_t> encapsulated_key) const {
            if (!m_kem_mode) {
                throw NoiseError("Decapsulate() only supported for KEM algorithms (M512, M768, M1024)");
            }

            Botan::System_RNG rng;

            // Reconstruct private key from bytes
            const Botan::ML_KEM_Mode mode = GetMLKEMMode();
            Botan::ML_KEM_PrivateKey priv_key(my_private_key, mode);

            // Create decryptor and perform decapsulation
            Botan::PK_KEM_Decryptor decryptor(priv_key, rng, "Raw");

            // Decrypt using the proper API (returns secure_vector)
            auto shared_secret = decryptor.decrypt(encapsulated_key.data(),
                                                    encapsulated_key.size(),
                                                    m_dhLen);

            return {shared_secret.begin(), shared_secret.end()};
        }

        void PrintKeys(const KeyPair& keypair) const {
            std::println("Algorithm: {}", m_algoName);

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
            return m_algoName;
        }

    private:
        /** Maps the m_kem_level string to Botan's ML_KEM_Mode enum. */
        [[nodiscard]] Botan::ML_KEM_Mode GetMLKEMMode() const {
            if (m_kem_level == "ML-KEM-512") {
                return Botan::ML_KEM_Mode::ML_KEM_512;
            }
            else if (m_kem_level == "ML-KEM-768") {
                return Botan::ML_KEM_Mode::ML_KEM_768;
            }
            else if (m_kem_level == "ML-KEM-1024") {
                return Botan::ML_KEM_Mode::ML_KEM_1024;
            }
            throw NoiseError("Invalid ML-KEM mode: " + m_botan_name);
        }

        const std::string m_algoName;
        std::uint8_t m_dhLen;
        std::string m_botan_name;
        std::string m_kem_level{};
        bool m_kem_mode = false;
    };
}