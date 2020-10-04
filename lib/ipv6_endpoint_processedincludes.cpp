///////////////////////////////////////////////////////////////////////////////
// Kt C++ Library
// Copyright (c) 2015 Lewis Baker
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IPV6_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IPV6_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IPV6_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IPV6_ADDRESS_HPP_INCLUDED

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace cppcoro::net
{
	class ipv4_address;

	class ipv6_address
	{
		using bytes_t = std::uint8_t[16];

	public:

		constexpr ipv6_address();

		explicit constexpr ipv6_address(
			std::uint64_t subnetPrefix,
			std::uint64_t interfaceIdentifier);

		constexpr ipv6_address(
			std::uint16_t part0,
			std::uint16_t part1,
			std::uint16_t part2,
			std::uint16_t part3,
			std::uint16_t part4,
			std::uint16_t part5,
			std::uint16_t part6,
			std::uint16_t part7);

		explicit constexpr ipv6_address(
			const std::uint16_t(&parts)[8]);

		explicit constexpr ipv6_address(
			const std::uint8_t(&bytes)[16]);

		constexpr const bytes_t& bytes() const { return m_bytes; }

		constexpr std::uint64_t subnet_prefix() const;

		constexpr std::uint64_t interface_identifier() const;

		/// Get the IPv6 unspedified address :: (all zeroes).
		static constexpr ipv6_address unspecified();

		/// Get the IPv6 loopback address ::1.
		static constexpr ipv6_address loopback();

		/// Parse a string representation of an IPv6 address.
		///
		/// \param string
		/// The string to parse.
		/// Must be in ASCII, UTF-8 or Latin-1 encoding.
		///
		/// \return
		/// The IP address if successful, otherwise std::nullopt if the string
		/// could not be parsed as an IPv4 address.
		static std::optional<ipv6_address> from_string(std::string_view string) noexcept;

		/// Convert the IP address to contracted string form.
		///
		/// Address is broken up into 16-bit parts, with each part represended in 1-4
		/// lower-case hexadecimal with leading zeroes omitted. Parts are separated
		/// by separated by a ':'. The longest contiguous run of zero parts is contracted
		/// to "::".
		///
		/// For example:
		/// ipv6_address::unspecified() -> "::"
		/// ipv6_address::loopback() -> "::1"
		/// ipv6_address(0x0011223344556677, 0x8899aabbccddeeff) ->
		///   "11:2233:4455:6677:8899:aabb:ccdd:eeff"
		/// ipv6_address(0x0102030400000000, 0x003fc447ab991011) ->
		///   "102:304::3f:c447:ab99:1011"
		std::string to_string() const;

		constexpr bool operator==(const ipv6_address& other) const;
		constexpr bool operator!=(const ipv6_address& other) const;
		constexpr bool operator<(const ipv6_address& other) const;
		constexpr bool operator>(const ipv6_address& other) const;
		constexpr bool operator<=(const ipv6_address& other) const;
		constexpr bool operator>=(const ipv6_address& other) const;

	private:

		alignas(std::uint64_t) std::uint8_t m_bytes[16];

	};

	constexpr ipv6_address::ipv6_address()
		: m_bytes{
			0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0 }
	{}

	constexpr ipv6_address::ipv6_address(
		std::uint64_t subnetPrefix,
		std::uint64_t interfaceIdentifier)
		: m_bytes{
			static_cast<std::uint8_t>(subnetPrefix >> 56),
			static_cast<std::uint8_t>(subnetPrefix >> 48),
			static_cast<std::uint8_t>(subnetPrefix >> 40),
			static_cast<std::uint8_t>(subnetPrefix >> 32),
			static_cast<std::uint8_t>(subnetPrefix >> 24),
			static_cast<std::uint8_t>(subnetPrefix >> 16),
			static_cast<std::uint8_t>(subnetPrefix >> 8),
			static_cast<std::uint8_t>(subnetPrefix),
			static_cast<std::uint8_t>(interfaceIdentifier >> 56),
			static_cast<std::uint8_t>(interfaceIdentifier >> 48),
			static_cast<std::uint8_t>(interfaceIdentifier >> 40),
			static_cast<std::uint8_t>(interfaceIdentifier >> 32),
			static_cast<std::uint8_t>(interfaceIdentifier >> 24),
			static_cast<std::uint8_t>(interfaceIdentifier >> 16),
			static_cast<std::uint8_t>(interfaceIdentifier >> 8),
			static_cast<std::uint8_t>(interfaceIdentifier) }
	{}

	constexpr ipv6_address::ipv6_address(
		std::uint16_t part0,
		std::uint16_t part1,
		std::uint16_t part2,
		std::uint16_t part3,
		std::uint16_t part4,
		std::uint16_t part5,
		std::uint16_t part6,
		std::uint16_t part7)
		: m_bytes{
			static_cast<std::uint8_t>(part0 >> 8),
			static_cast<std::uint8_t>(part0),
			static_cast<std::uint8_t>(part1 >> 8),
			static_cast<std::uint8_t>(part1),
			static_cast<std::uint8_t>(part2 >> 8),
			static_cast<std::uint8_t>(part2),
			static_cast<std::uint8_t>(part3 >> 8),
			static_cast<std::uint8_t>(part3),
			static_cast<std::uint8_t>(part4 >> 8),
			static_cast<std::uint8_t>(part4),
			static_cast<std::uint8_t>(part5 >> 8),
			static_cast<std::uint8_t>(part5),
			static_cast<std::uint8_t>(part6 >> 8),
			static_cast<std::uint8_t>(part6),
			static_cast<std::uint8_t>(part7 >> 8),
			static_cast<std::uint8_t>(part7) }
	{}

	constexpr ipv6_address::ipv6_address(
		const std::uint16_t(&parts)[8])
		: ipv6_address(
			parts[0], parts[1], parts[2], parts[3],
			parts[4], parts[5], parts[6], parts[7])
	{}

	constexpr ipv6_address::ipv6_address(const std::uint8_t(&bytes)[16])
		: m_bytes{
			bytes[0], bytes[1], bytes[2], bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7],
			bytes[8], bytes[9], bytes[10], bytes[11],
			bytes[12], bytes[13], bytes[14], bytes[15] }
	{}

	constexpr std::uint64_t ipv6_address::subnet_prefix() const
	{
		return
			static_cast<std::uint64_t>(m_bytes[0]) << 56 |
			static_cast<std::uint64_t>(m_bytes[1]) << 48 |
			static_cast<std::uint64_t>(m_bytes[2]) << 40 |
			static_cast<std::uint64_t>(m_bytes[3]) << 32 |
			static_cast<std::uint64_t>(m_bytes[4]) << 24 |
			static_cast<std::uint64_t>(m_bytes[5]) << 16 |
			static_cast<std::uint64_t>(m_bytes[6]) << 8 |
			static_cast<std::uint64_t>(m_bytes[7]);
	}

	constexpr std::uint64_t ipv6_address::interface_identifier() const
	{
		return
			static_cast<std::uint64_t>(m_bytes[8]) << 56 |
			static_cast<std::uint64_t>(m_bytes[9]) << 48 |
			static_cast<std::uint64_t>(m_bytes[10]) << 40 |
			static_cast<std::uint64_t>(m_bytes[11]) << 32 |
			static_cast<std::uint64_t>(m_bytes[12]) << 24 |
			static_cast<std::uint64_t>(m_bytes[13]) << 16 |
			static_cast<std::uint64_t>(m_bytes[14]) << 8 |
			static_cast<std::uint64_t>(m_bytes[15]);
	}

	constexpr ipv6_address ipv6_address::unspecified()
	{
		return ipv6_address{};
	}

	constexpr ipv6_address ipv6_address::loopback()
	{
		return ipv6_address{ 0, 0, 0, 0, 0, 0, 0, 1 };
	}

	constexpr bool ipv6_address::operator==(const ipv6_address& other) const
	{
		for (int i = 0; i < 16; ++i)
		{
			if (m_bytes[i] != other.m_bytes[i]) return false;
		}
		return true;
	}

	constexpr bool ipv6_address::operator!=(const ipv6_address& other) const
	{
		return !(*this == other);
	}

	constexpr bool ipv6_address::operator<(const ipv6_address& other) const
	{
		for (int i = 0; i < 16; ++i)
		{
			if (m_bytes[i] != other.m_bytes[i])
				return m_bytes[i] < other.m_bytes[i];
		}

		return false;
	}

	constexpr bool ipv6_address::operator>(const ipv6_address& other) const
	{
		return (other < *this);
	}

	constexpr bool ipv6_address::operator<=(const ipv6_address& other) const
	{
		return !(other < *this);
	}

	constexpr bool ipv6_address::operator>=(const ipv6_address& other) const
	{
		return !(*this < other);
	}
}

#endif

#include <optional>
#include <string>
#include <string_view>

namespace cppcoro
{
	namespace net
	{
		class ipv6_endpoint
		{
		public:

			// Construct to [::]:0
			ipv6_endpoint() noexcept
				: m_address()
				, m_port(0)
			{}

			explicit ipv6_endpoint(ipv6_address address, std::uint16_t port = 0) noexcept
				: m_address(address)
				, m_port(port)
			{}

			const ipv6_address& address() const noexcept { return m_address; }

			std::uint16_t port() const noexcept { return m_port; }

			std::string to_string() const;

			static std::optional<ipv6_endpoint> from_string(std::string_view string) noexcept;

		private:

			ipv6_address m_address;
			std::uint16_t m_port;

		};

		inline bool operator==(const ipv6_endpoint& a, const ipv6_endpoint& b)
		{
			return a.address() == b.address() &&
				a.port() == b.port();
		}

		inline bool operator!=(const ipv6_endpoint& a, const ipv6_endpoint& b)
		{
			return !(a == b);
		}

		inline bool operator<(const ipv6_endpoint& a, const ipv6_endpoint& b)
		{
			return a.address() < b.address() ||
				(a.address() == b.address() && a.port() < b.port());
		}

		inline bool operator>(const ipv6_endpoint& a, const ipv6_endpoint& b)
		{
			return b < a;
		}

		inline bool operator<=(const ipv6_endpoint& a, const ipv6_endpoint& b)
		{
			return !(b < a);
		}

		inline bool operator>=(const ipv6_endpoint& a, const ipv6_endpoint& b)
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

std::string cppcoro::net::ipv6_endpoint::to_string() const
{
	std::string result;
	result.push_back('[');
	result += m_address.to_string();
	result += "]:";
	result += std::to_string(m_port);
	return result;
}

std::optional<cppcoro::net::ipv6_endpoint>
cppcoro::net::ipv6_endpoint::from_string(std::string_view string) noexcept
{
	// Shortest valid endpoint is "[::]:0"
	if (string.size() < 6)
	{
		return std::nullopt;
	}

	if (string[0] != '[')
	{
		return std::nullopt;
	}

	auto closeBracketPos = string.find("]:", 1);
	if (closeBracketPos == std::string_view::npos)
	{
		return std::nullopt;
	}

	auto address = ipv6_address::from_string(string.substr(1, closeBracketPos - 1));
	if (!address)
	{
		return std::nullopt;
	}

	auto port = local::parse_port(string.substr(closeBracketPos + 2));
	if (!port)
	{
		return std::nullopt;
	}

	return ipv6_endpoint{ *address, *port };
}
