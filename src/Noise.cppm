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


/**
 * @brief Facade module for the NoisePQC++ library.
 *
 * Application code should `import noise;` to access the full public API.
 * Re-exports all submodules: common types, error hierarchy, cryptographic
 * primitives (Cipher, Hash, Dh), protocol state (CipherState, SymmetricState),
 * handshake patterns, protocol configuration, and the HandshakeState machine.
 *
 * In debug builds (NOISE_DEBUG_BUILD), instrumented variants with state
 * transition logging are substituted for CipherState, SymmetricState,
 * and HandshakeState.
 */
export module noise;

export import :common;
export import :errors;
export import :cipher;
export import :hash;
export import :dh;
export import :pattern;
export import :protocol;

#ifdef NOISE_DEBUG_BUILD
export import :cipherstate.debug;
export import :symmetricstate.debug;
export import :handshakestate.debug;
#else
export import :cipherstate;
export import :symmetricstate;
export import :handshakestate;
#endif
