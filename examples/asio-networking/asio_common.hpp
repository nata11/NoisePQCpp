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

#ifndef NOISEPQC_ASIO_COMMON_HPP
#define NOISEPQC_ASIO_COMMON_HPP

#include <asio.hpp>
import std;

using asio::ip::tcp;

namespace NoiseAsio {

// Protocol configuration
constexpr std::string_view PROTOCOL_STRING = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
constexpr std::uint16_t DEFAULT_PORT = 12345;
constexpr std::size_t MAX_MESSAGE_SIZE = 65535;  // Noise protocol limit

// ============================================================================
// Message Framing
// ============================================================================
// TCP is stream-based, so we need length-prefix framing to delimit messages.
// Format: [4-byte big-endian length][message bytes]

// Send a framed message over TCP socket
inline void send_framed(tcp::socket& socket, std::span<const std::uint8_t> data) {
    if (data.size() > MAX_MESSAGE_SIZE) {
        throw std::runtime_error("Message exceeds maximum size");
    }

    // Create 4-byte big-endian length prefix
    std::uint32_t length = static_cast<std::uint32_t>(data.size());
    std::array<std::uint8_t, 4> header{
        static_cast<std::uint8_t>((length >> 24) & 0xFF),
        static_cast<std::uint8_t>((length >> 16) & 0xFF),
        static_cast<std::uint8_t>((length >> 8) & 0xFF),
        static_cast<std::uint8_t>(length & 0xFF)
    };

    // Send header
    asio::write(socket, asio::buffer(header));

    // Send payload
    if (!data.empty()) {
        asio::write(socket, asio::buffer(data.data(), data.size()));
    }
}

// Receive a framed message from TCP socket
inline std::vector<std::uint8_t> recv_framed(tcp::socket& socket) {
    // Read 4-byte length header
    std::array<std::uint8_t, 4> header{};
    asio::read(socket, asio::buffer(header));

    // Parse big-endian length
    std::uint32_t length =
        (static_cast<std::uint32_t>(header[0]) << 24) |
        (static_cast<std::uint32_t>(header[1]) << 16) |
        (static_cast<std::uint32_t>(header[2]) << 8) |
        static_cast<std::uint32_t>(header[3]);

    if (length > MAX_MESSAGE_SIZE) {
        throw std::runtime_error("Received message exceeds maximum size");
    }

    // Read payload
    std::vector<std::uint8_t> data(length);
    if (length > 0) {
        asio::read(socket, asio::buffer(data));
    }

    return data;
}

// ============================================================================
// String/Bytes Conversion Helpers
// ============================================================================

// Convert string_view to vector<uint8_t>
inline std::vector<std::uint8_t> to_bytes(std::string_view str) {
    return std::vector<std::uint8_t>(str.begin(), str.end());
}

// Convert span<uint8_t> to string
inline std::string to_string(std::span<const std::uint8_t> bytes) {
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

// ============================================================================
// Display Helpers
// ============================================================================

inline void print_separator(std::string_view title = "") {
    if (title.empty()) {
        std::println("{}", std::string(60, '='));
    } else {
        std::println("\n{}", std::string(60, '='));
        std::println("  {}", title);
        std::println("{}", std::string(60, '='));
    }
}

inline void print_bytes_hex(std::string_view label, std::span<const std::uint8_t> data, std::size_t max_bytes = 16) {
    std::print("  {}: ", label);
    std::size_t show = std::min(data.size(), max_bytes);
    for (std::size_t i = 0; i < show; ++i) {
        std::print("{:02x}", data[i]);
    }
    if (data.size() > max_bytes) {
        std::print("...");
    }
    std::println(" ({} bytes)", data.size());
}

} // namespace NoiseAsio

#endif // NOISEPQC_ASIO_COMMON_HPP
