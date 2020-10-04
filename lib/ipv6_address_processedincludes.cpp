///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CONFIG_HPP_INCLUDED
#define CPPCORO_CONFIG_HPP_INCLUDED

/////////////////////////////////////////////////////////////////////////////
// Compiler Detection

#if defined(_MSC_VER)
# define CPPCORO_COMPILER_MSVC _MSC_FULL_VER
#else
# define CPPCORO_COMPILER_MSVC 0
#endif

#if defined(__clang__)
# define CPPCORO_COMPILER_CLANG (__clang_major__ * 10000 + \
                                 __clang_minor__ * 100 + \
                                 __clang_patchlevel__)
#else
# define CPPCORO_COMPILER_CLANG 0
#endif

#if defined(__GNUC__)
# define CPPCORO_COMPILER_GCC (__GNUC__ * 10000 + \
                               __GNUC_MINOR__ * 100 + \
                               __GNUC_PATCHLEVEL__)
#else
# define CPPCORO_COMPILER_GCC 0
#endif

/// \def CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
/// Defined to 1 if the compiler supports returning a coroutine_handle from
/// the await_suspend() method as a way of transferring execution
/// to another coroutine with a guaranteed tail-call.
#if CPPCORO_COMPILER_CLANG
# if __clang_major__ >= 7
#  define CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER 1
# endif
#endif
#ifndef CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
# define CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER 0
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_ASSUME(X) __assume(X)
#else
# define CPPCORO_ASSUME(X)
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_NOINLINE __declspec(noinline)
#elif CPPCORO_COMPILER_CLANG || CPPCORO_COMPILER_GCC
# define CPPCORO_NOINLINE __attribute__((noinline))
#else
# define CPPCORO_NOINLINE
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_FORCE_INLINE __forceinline
#elif CPPCORO_COMPILER_CLANG
# define CPPCORO_FORCE_INLINE __attribute__((always_inline))
#else
# define CPPCORO_FORCE_INLINE inline
#endif

/////////////////////////////////////////////////////////////////////////////
// OS Detection

/// \def CPPCORO_OS_WINNT
/// Defined to non-zero if the target platform is a WindowsNT variant.
/// 0x0500 - Windows 2000
/// 0x0501 - Windows XP/Server 2003
/// 0x0502 - Windows XP SP2/Server 2003 SP1
/// 0x0600 - Windows Vista/Server 2008
/// 0x0601 - Windows 7
/// 0x0602 - Windows 8
/// 0x0603 - Windows 8.1
/// 0x0A00 - Windows 10
#if defined(_WIN32_WINNT) || defined(_WIN32)
# if !defined(_WIN32_WINNT)
// Default to targeting Windows 10 if not defined.
#  define _WIN32_WINNT 0x0A00
# endif
# define CPPCORO_OS_WINNT _WIN32_WINNT
#else
# define CPPCORO_OS_WINNT 0
#endif

#if defined(__linux__)
# define CPPCORO_OS_LINUX 1
#else
# define CPPCORO_OS_LINUX 0
#endif

/////////////////////////////////////////////////////////////////////////////
// CPU Detection

/// \def CPPCORO_CPU_X86
/// Defined to 1 if target CPU is of x86 family.
#if CPPCORO_COMPILER_MSVC
# if defined(_M_IX86)
#  define CPPCORO_CPU_X86 1
# endif
#elif CPPCORO_COMPILER_GCC || CPPCORO_COMPILER_CLANG
# if defined(__i386__)
#  define CPPCORO_CPU_X86 1
# endif
#endif
#if !defined(CPPCORO_CPU_X86)
# define CPPCORO_CPU_X86 0
#endif

/// \def CPPCORO_CPU_X64
/// Defined to 1 if the target CPU is x64 family.
#if CPPCORO_COMPILER_MSVC
# if defined(_M_X64)
#  define CPPCORO_CPU_X64 1
# endif
#elif CPPCORO_COMPILER_GCC || CPPCORO_COMPILER_CLANG
# if defined(__x86_64__)
#  define CPPCORO_CPU_X64 1
# endif
#endif
#if !defined(CPPCORO_CPU_X64)
# define CPPCORO_CPU_X64 0
#endif

/// \def CPPCORO_CPU_32BIT
/// Defined if compiling for a 32-bit CPU architecture.
#if CPPCORO_CPU_X86
# define CPPCORO_CPU_32BIT 1
#else
# define CPPCORO_CPU_32BIT 0
#endif

/// \def CPPCORO_CPU_64BIT
/// Defined if compiling for a 64-bit CPU architecture.
#if CPPCORO_CPU_X64
# define CPPCORO_CPU_64BIT 1
#else
# define CPPCORO_CPU_64BIT 0
#endif

#if CPPCORO_COMPILER_MSVC
# define CPPCORO_CPU_CACHE_LINE std::hardware_destructive_interference_size
#else
// On most architectures we can assume a 64-byte cache line.
# define CPPCORO_CPU_CACHE_LINE 64
#endif

#endif

#include <cassert>

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

		std::optional<std::uint8_t> try_parse_hex_digit(char c)
		{
			if (c >= '0' && c <= '9')
			{
				return static_cast<std::uint8_t>(c - '0');
			}
			else if (c >= 'a' && c <= 'f')
			{
				return static_cast<std::uint8_t>(c - 'a' + 10);
			}
			else if (c >= 'A' && c <= 'F')
			{
				return static_cast<std::uint8_t>(c - 'A' + 10);
			}

			return std::nullopt;
		}

		char hex_char(std::uint8_t value)
		{
			return value < 10 ?
				static_cast<char>('0' + value) :
				static_cast<char>('a' + value - 10);
		}
	}
}

std::optional<cppcoro::net::ipv6_address>
cppcoro::net::ipv6_address::from_string(std::string_view string) noexcept
{
	// Longest possible valid IPv6 string is
	// "xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:nnn.nnn.nnn.nnn"
	constexpr std::size_t maxLength = 45;

	if (string.empty() || string.length() > maxLength)
	{
		return std::nullopt;
	}

	const std::size_t length = string.length();

	std::optional<int> doubleColonPos;

	std::size_t pos = 0;

	if (length >= 2 && string[0] == ':' && string[1] == ':')
	{
		doubleColonPos = 0;
		pos = 2;
	}

	int partCount = 0;
	std::uint16_t parts[8] = { 0 };

	while (pos < length && partCount < 8)
	{
		std::uint8_t digits[4];
		int digitCount = 0;
		auto digit = local::try_parse_hex_digit(string[pos]);
		if (!digit)
		{
			return std::nullopt;
		}

		do
		{
			digits[digitCount] = *digit;
			++digitCount;
			++pos;
		} while (digitCount < 4 && pos < length && (digit = local::try_parse_hex_digit(string[pos])));

		// If we're not at the end of the string then there must either be a ':' or a '.' next
		// followed by the next part.
		if (pos < length)
		{
			// Check if there's room for anything after the separator.
			if ((pos + 1) == length)
			{
				return std::nullopt;
			}

			if (string[pos] == ':')
			{
				++pos;
				if (string[pos] == ':')
				{
					if (doubleColonPos)
					{
						// This is a second double-colon, which is invalid.
						return std::nullopt;
					}

					doubleColonPos = partCount + 1;
					++pos;
				}
			}
			else if (string[pos] == '.')
			{
				// Treat the current set of digits as decimal digits and parse
				// the remaining three groups as dotted decimal notation.

				// Decimal notation produces two 16-bit parts.
				// If we already have more than 6 parts then we'll end up
				// with too many.
				if (partCount > 6)
				{
					return std::nullopt;
				}

				// Check for over-long or octal notation.
				if (digitCount > 3 || (digitCount > 1 && digits[0] == 0))
				{
					return std::nullopt;
				}

				// Check that digits are valid decimal digits
				if (digits[0] > 9 ||
					(digitCount > 1 && digits[1] > 9) ||
					(digitCount == 3 && digits[2] > 9))
				{
					return std::nullopt;
				}

				std::uint16_t decimalParts[4];

				{
					decimalParts[0] = digits[0];
					for (int i = 1; i < digitCount; ++i)
					{
						decimalParts[0] *= 10;
						decimalParts[0] += digits[i];
					}

					if (decimalParts[0] > 255)
					{
						return std::nullopt;
					}
				}

				for (int decimalPart = 1; decimalPart < 4; ++decimalPart)
				{
					if (string[pos] != '.')
					{
						return std::nullopt;
					}

					++pos;

					if (pos == length || !local::is_digit(string[pos]))
					{
						// Expected a number after a dot.
						return std::nullopt;
					}

					const bool hasLeadingZero = string[pos] == '0';

					decimalParts[decimalPart] = local::digit_value(string[pos]);
					++pos;
					digitCount = 1;
					while (digitCount < 3 && pos < length && local::is_digit(string[pos]))
					{
						decimalParts[decimalPart] *= 10;
						decimalParts[decimalPart] += local::digit_value(string[pos]);
						++pos;
						++digitCount;
					}

					if (decimalParts[decimalPart] > 255)
					{
						return std::nullopt;
					}

					// Detect octal-style number (redundant leading zero)
					if (digitCount > 1 && hasLeadingZero)
					{
						return std::nullopt;
					}
				}

				parts[partCount] = (decimalParts[0] << 8) + decimalParts[1];
				parts[partCount + 1] = (decimalParts[2] << 8) + decimalParts[3];
				partCount += 2;

				// Dotted decimal notation only appears at end.
				// Don't parse any more of the string.
				break;
			}
			else
			{
				// Invalid separator.
				return std::nullopt;
			}
		}

		// Current part was made up of hex-digits.
		std::uint16_t partValue = digits[0];
		for (int i = 1; i < digitCount; ++i)
		{
			partValue = partValue * 16 + digits[i];
		}

		parts[partCount] = partValue;
		++partCount;
	}

	// Finished parsing the IPv6 address, we should have consumed all of the string.
	if (pos < length)
	{
		return std::nullopt;
	}

	if (partCount < 8)
	{
		if (!doubleColonPos)
		{
			return std::nullopt;
		}

		const int preCount = *doubleColonPos;

		//CPPCORO_ASSUME(preCount <= partCount);

		const int postCount = partCount - preCount;
		const int zeroCount = 8 - preCount - postCount;

		// Move parts after double colon down to the end.
		for (int i = 0; i < postCount; ++i)
		{
			parts[7 - i] = parts[7 - zeroCount - i];
		}

		// Fill gap with zeroes.
		for (int i = 0; i < zeroCount; ++i)
		{
			parts[preCount + i] = 0;
		}
	}
	else if (doubleColonPos)
	{
		return std::nullopt;
	}

	return ipv6_address{ parts };
}

std::string cppcoro::net::ipv6_address::to_string() const
{
	std::uint32_t longestZeroRunStart = 0;
	std::uint32_t longestZeroRunLength = 0;
	for (std::uint32_t i = 0; i < 8; )
	{
		if (m_bytes[2 * i] == 0 && m_bytes[2 * i + 1] == 0)
		{
			const std::uint32_t zeroRunStart = i;
			++i;
			while (i < 8 && m_bytes[2 * i] == 0 && m_bytes[2 * i + 1] == 0)
			{
				++i;
			}

			std::uint32_t zeroRunLength = i - zeroRunStart;
			if (zeroRunLength > longestZeroRunLength)
			{
				longestZeroRunLength = zeroRunLength;
				longestZeroRunStart = zeroRunStart;
			}
		}
		else
		{
			++i;
		}
	}

	// Longest string will be 8 x 4 digits + 7 ':' separators
	char buffer[40];

	char* c = &buffer[0];

	auto appendPart = [&](std::uint32_t index)
	{
		const std::uint8_t highByte = m_bytes[index * 2];
		const std::uint8_t lowByte = m_bytes[index * 2 + 1];

		// Don't output leading zero hex digits in the part string.
		if (highByte > 0 || lowByte > 15)
		{
			if (highByte > 0)
			{
				if (highByte > 15)
				{
					*c++ = local::hex_char(highByte >> 4);
				}
				*c++ = local::hex_char(highByte & 0xF);
			}
			*c++ = local::hex_char(lowByte >> 4);
		}
		*c++ = local::hex_char(lowByte & 0xF);
	};

	if (longestZeroRunLength >= 2)
	{
		for (std::uint32_t i = 0; i < longestZeroRunStart; ++i)
		{
			if (i > 0)
			{
				*c++ = ':';
			}

			appendPart(i);
		}

		*c++ = ':';
		*c++ = ':';

		for (std::uint32_t i = longestZeroRunStart + longestZeroRunLength; i < 8; ++i)
		{
			appendPart(i);

			if (i < 7)
			{
				*c++ = ':';
			}
		}
	}
	else
	{
		appendPart(0);
		for (std::uint32_t i = 1; i < 8; ++i)
		{
			*c++ = ':';
			appendPart(i);
		}
	}

	assert((c - &buffer[0]) <= sizeof(buffer));

	return std::string{ &buffer[0], c };
}
