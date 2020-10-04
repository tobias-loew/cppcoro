///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

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

namespace
{
	namespace local
	{
		constexpr bool is_digit(char c)
		{
			return c >= '0' && c <= '9';
		}

		constexpr std::uint8_t digit_value(char c)
		{
			return static_cast<std::uint8_t>(c - '0');
		}
	}
}

std::optional<cppcoro::net::ipv4_address>
cppcoro::net::ipv4_address::from_string(std::string_view string) noexcept
{
	if (string.empty()) return std::nullopt;

	if (!local::is_digit(string[0]))
	{
		return std::nullopt;
	}

	const auto length = string.length();

	std::uint8_t partValues[4];

	if (string[0] == '0' && length > 1)
	{
		if (local::is_digit(string[1]))
		{
			// Octal format (not supported)
			return std::nullopt;
		}
		else if (string[1] == 'x')
		{
			// Hexadecimal format (not supported)
			return std::nullopt;
		}
	}

	// Parse the first integer.
	// Could be a single 32-bit integer or first integer in a dotted decimal string.

	std::size_t pos = 0;

	{
		constexpr std::uint32_t maxValue = 0xFFFFFFFFu / 10;
		constexpr std::uint32_t maxDigit = 0xFFFFFFFFu % 10;

		std::uint32_t partValue = local::digit_value(string[pos]);
		++pos;

		while (pos < length && local::is_digit(string[pos]))
		{
			const auto digitValue = local::digit_value(string[pos]);
			++pos;

			// Check if this digit would overflow the 32-bit integer
			if (partValue > maxValue || (partValue == maxValue && digitValue > maxDigit))
			{
				return std::nullopt;
			}

			partValue = (partValue * 10) + digitValue;
		}

		if (pos == length)
		{
			// A single-integer string
			return ipv4_address{ partValue };
		}
		else if (partValue > 255)
		{
			// Not a valid first component of dotted decimal
			return std::nullopt;
		}

		partValues[0] = static_cast<std::uint8_t>(partValue);
	}

	for (int part = 1; part < 4; ++part)
	{
		if ((pos + 1) >= length || string[pos] != '.' || !local::is_digit(string[pos + 1]))
		{
			return std::nullopt;
		}

		// Skip the '.'
		++pos;

		// Check for an octal format (not yet supported)
		const bool isPartOctal =
			(pos + 1) < length &&
			string[pos] == '0' &&
			local::is_digit(string[pos + 1]);
		if (isPartOctal)
		{
			return std::nullopt;
		}

		std::uint32_t partValue = local::digit_value(string[pos]);
		++pos;
		if (pos < length && local::is_digit(string[pos]))
		{
			partValue = (partValue * 10) + local::digit_value(string[pos]);
			++pos;
			if (pos < length && local::is_digit(string[pos]))
			{
				partValue = (partValue * 10) + local::digit_value(string[pos]);
				if (partValue > 255)
				{
					return std::nullopt;
				}

				++pos;
			}
		}

		partValues[part] = static_cast<std::uint8_t>(partValue);
	}

	if (pos < length)
	{
		// Extra chars after end of a valid IPv4 string
		return std::nullopt;
	}

	return ipv4_address{ partValues };
}

std::string cppcoro::net::ipv4_address::to_string() const
{
	// Buffer is large enough to hold larges ip address
	// "xxx.xxx.xxx.xxx"
	char buffer[15];

	char* c = &buffer[0];
	for (int i = 0; i < 4; ++i)
	{
		if (i > 0)
		{
			*c++ = '.';
		}

		if (m_bytes[i] >= 100)
		{
			*c++ = '0' + (m_bytes[i] / 100);
			*c++ = '0' + (m_bytes[i] % 100) / 10;
			*c++ = '0' + (m_bytes[i] % 10);
		}
		else if (m_bytes[i] >= 10)
		{
			*c++ = '0' + (m_bytes[i] / 10);
			*c++ = '0' + (m_bytes[i] % 10);
		}
		else
		{
			*c++ = '0' + m_bytes[i];
		}
	}

	return std::string{ &buffer[0], c };
}
