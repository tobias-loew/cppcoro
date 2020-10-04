///////////////////////////////////////////////////////////////////////////////
// Kt C++ Library
// Copyright (c) 2015 Lewis Baker
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IPV4_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IPV4_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IPV4_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IPV4_ADDRESS_HPP_INCLUDED

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace cppcoro::net
{
	class ipv4_address
	{
		using bytes_t = std::uint8_t[4];

	public:

		constexpr ipv4_address()
			: m_bytes{ 0, 0, 0, 0 }
		{}

		explicit constexpr ipv4_address(std::uint32_t integer)
			: m_bytes{
			static_cast<std::uint8_t>(integer >> 24),
			static_cast<std::uint8_t>(integer >> 16),
			static_cast<std::uint8_t>(integer >> 8),
			static_cast<std::uint8_t>(integer) }
		{}

		explicit constexpr ipv4_address(const std::uint8_t(&bytes)[4])
			: m_bytes{ bytes[0], bytes[1], bytes[2], bytes[3] }
		{}

		explicit constexpr ipv4_address(
			std::uint8_t b0,
			std::uint8_t b1,
			std::uint8_t b2,
			std::uint8_t b3)
			: m_bytes{ b0, b1, b2, b3 }
		{}

		constexpr const bytes_t& bytes() const { return m_bytes; }

		constexpr std::uint32_t to_integer() const
		{
			return
				std::uint32_t(m_bytes[0]) << 24 |
				std::uint32_t(m_bytes[1]) << 16 |
				std::uint32_t(m_bytes[2]) << 8 |
				std::uint32_t(m_bytes[3]);
		}

		static constexpr ipv4_address loopback()
		{
			return ipv4_address(127, 0, 0, 1);
		}

		constexpr bool is_loopback() const
		{
			return m_bytes[0] == 127;
		}

		constexpr bool is_private_network() const
		{
			return m_bytes[0] == 10 ||
				(m_bytes[0] == 172 && (m_bytes[1] & 0xF0) == 0x10) ||
				(m_bytes[0] == 192 && m_bytes[2] == 168);
		}

		constexpr bool operator==(ipv4_address other) const
		{
			return
				m_bytes[0] == other.m_bytes[0] &&
				m_bytes[1] == other.m_bytes[1] &&
				m_bytes[2] == other.m_bytes[2] &&
				m_bytes[3] == other.m_bytes[3];
		}

		constexpr bool operator!=(ipv4_address other) const
		{
			return !(*this == other);
		}

		constexpr bool operator<(ipv4_address other) const
		{
			return to_integer() < other.to_integer();
		}

		constexpr bool operator>(ipv4_address other) const
		{
			return other < *this;
		}

		constexpr bool operator<=(ipv4_address other) const
		{
			return !(other < *this);
		}

		constexpr bool operator>=(ipv4_address other) const
		{
			return !(*this < other);
		}

		/// Parse a string representation of an IP address.
		///
		/// Parses strings of the form:
		/// - "num.num.num.num" where num is an integer in range [0, 255].
		/// - A single integer value in range [0, 2^32).
		///
		/// \param string
		/// The string to parse.
		/// Must be in ASCII, UTF-8 or Latin-1 encoding.
		///
		/// \return
		/// The IP address if successful, otherwise std::nullopt if the string
		/// could not be parsed as an IPv4 address.
		static std::optional<ipv4_address> from_string(std::string_view string) noexcept;

		/// Convert the IP address to dotted decimal notation.
		///
		/// eg. "12.67.190.23"
		std::string to_string() const;

	private:

		alignas(std::uint32_t) std::uint8_t m_bytes[4];

	};
}

#endif

#include <optional>
#include <string>
#include <string_view>

namespace cppcoro
{
	namespace net
	{
		class ipv4_endpoint
		{
		public:

			// Construct to 0.0.0.0:0
			ipv4_endpoint() noexcept
				: m_address()
				, m_port(0)
			{}

			explicit ipv4_endpoint(ipv4_address address, std::uint16_t port = 0) noexcept
				: m_address(address)
				, m_port(port)
			{}

			const ipv4_address& address() const noexcept { return m_address; }

			std::uint16_t port() const noexcept { return m_port; }

			std::string to_string() const;

			static std::optional<ipv4_endpoint> from_string(std::string_view string) noexcept;

		private:

			ipv4_address m_address;
			std::uint16_t m_port;

		};

		inline bool operator==(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return a.address() == b.address() &&
				a.port() == b.port();
		}

		inline bool operator!=(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return !(a == b);
		}

		inline bool operator<(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return a.address() < b.address() ||
				(a.address() == b.address() && a.port() < b.port());
		}

		inline bool operator>(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return b < a;
		}

		inline bool operator<=(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return !(b < a);
		}

		inline bool operator>=(const ipv4_endpoint& a, const ipv4_endpoint& b)
		{
			return !(a < b);
		}
	}
}

#endif

#include <algorithm>

namespace
{
	namespace local
	{
		bool is_digit(char c)
		{
			return c >= '0' && c <= '9';
		}

		std::uint8_t digit_value(char c)
		{
			return static_cast<std::uint8_t>(c - '0');
		}

		std::optional<std::uint16_t> parse_port(std::string_view string)
		{
			if (string.empty()) return std::nullopt;

			std::uint32_t value = 0;
			for (auto c : string)
			{
				if (!is_digit(c)) return std::nullopt;
				value = value * 10 + digit_value(c);
				if (value > 0xFFFFu) return std::nullopt;
			}

			return static_cast<std::uint16_t>(value);
		}
	}
}

std::string cppcoro::net::ipv4_endpoint::to_string() const
{
	auto s = m_address.to_string();
	s.push_back(':');
	s.append(std::to_string(m_port));
	return s;
}

std::optional<cppcoro::net::ipv4_endpoint>
cppcoro::net::ipv4_endpoint::from_string(std::string_view string) noexcept
{
	auto colonPos = string.find(':');
	if (colonPos == std::string_view::npos)
	{
		return std::nullopt;
	}

	auto address = ipv4_address::from_string(string.substr(0, colonPos));
	if (!address)
	{
		return std::nullopt;
	}

	auto port = local::parse_port(string.substr(colonPos + 1));
	if (!port)
	{
		return std::nullopt;
	}

	return ipv4_endpoint{ *address, *port };
}
