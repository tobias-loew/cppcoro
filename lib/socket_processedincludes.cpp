///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_HPP_INCLUDED

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

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED

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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_address
		{
		public:

			// Constructs to IPv4 address 0.0.0.0
			ip_address() noexcept;

			ip_address(ipv4_address address) noexcept;
			ip_address(ipv6_address address) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_address& to_ipv4() const;
			const ipv6_address& to_ipv6() const;

			const std::uint8_t* bytes() const noexcept;

			std::string to_string() const;

			static std::optional<ip_address> from_string(std::string_view string) noexcept;

			bool operator==(const ip_address& rhs) const noexcept;
			bool operator!=(const ip_address& rhs) const noexcept;

			//  ipv4_address sorts less than ipv6_address
			bool operator<(const ip_address& rhs) const noexcept;
			bool operator>(const ip_address& rhs) const noexcept;
			bool operator<=(const ip_address& rhs) const noexcept;
			bool operator>=(const ip_address& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_address m_ipv4;
				ipv6_address m_ipv6;
			};

		};

		inline ip_address::ip_address() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_address::ip_address(ipv4_address address) noexcept
			: m_family(family::ipv4)
			, m_ipv4(address)
		{}

		inline ip_address::ip_address(ipv6_address address) noexcept
			: m_family(family::ipv6)
			, m_ipv6(address)
		{
		}

		inline const ipv4_address& ip_address::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_address& ip_address::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline const std::uint8_t* ip_address::bytes() const noexcept
		{
			return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
		}

		inline bool ip_address::operator==(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator!=(const ip_address& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_address::operator<(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator>(const ip_address& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_address::operator<=(const ip_address& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_address::operator>=(const ip_address& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_endpoint
		{
		public:

			// Constructs to IPv4 end-point 0.0.0.0:0
			ip_endpoint() noexcept;

			ip_endpoint(ipv4_endpoint endpoint) noexcept;
			ip_endpoint(ipv6_endpoint endpoint) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_endpoint& to_ipv4() const;
			const ipv6_endpoint& to_ipv6() const;

			ip_address address() const noexcept;
			std::uint16_t port() const noexcept;

			std::string to_string() const;

			static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

			bool operator==(const ip_endpoint& rhs) const noexcept;
			bool operator!=(const ip_endpoint& rhs) const noexcept;

			//  ipv4_endpoint sorts less than ipv6_endpoint
			bool operator<(const ip_endpoint& rhs) const noexcept;
			bool operator>(const ip_endpoint& rhs) const noexcept;
			bool operator<=(const ip_endpoint& rhs) const noexcept;
			bool operator>=(const ip_endpoint& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_endpoint m_ipv4;
				ipv6_endpoint m_ipv6;
			};

		};

		inline ip_endpoint::ip_endpoint() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
			: m_family(family::ipv4)
			, m_ipv4(endpoint)
		{}

		inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
			: m_family(family::ipv6)
			, m_ipv6(endpoint)
		{
		}

		inline const ipv4_endpoint& ip_endpoint::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_endpoint& ip_endpoint::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline ip_address ip_endpoint::address() const noexcept
		{
			if (is_ipv4())
			{
				return m_ipv4.address();
			}
			else
			{
				return m_ipv6.address();
			}
		}

		inline std::uint16_t ip_endpoint::port() const noexcept
		{
			return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
		}

		inline bool ip_endpoint::operator==(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator!=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_endpoint::operator<(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator>(const ip_endpoint& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_endpoint::operator<=(const ip_endpoint& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_endpoint::operator>=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED
#define CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <functional>
#include <utility>
#include <type_traits>
#include <atomic>

namespace cppcoro
{
	namespace detail
	{
		class cancellation_state;
		struct cancellation_registration_list_chunk;
		struct cancellation_registration_state;
	}

	class cancellation_registration
	{
	public:

		/// Registers the callback to be executed when cancellation is requested
		/// on the cancellation_token.
		///
		/// The callback will be executed if cancellation is requested for the
		/// specified cancellation token. If cancellation has already been requested
		/// then the callback will be executed immediately, before the constructor
		/// returns. If cancellation has not yet been requested then the callback
		/// will be executed on the first thread to request cancellation inside
		/// the call to cancellation_source::request_cancellation().
		///
		/// \param token
		/// The cancellation token to register the callback with.
		///
		/// \param callback
		/// The callback to be executed when cancellation is requested on the
		/// the cancellation_token. Note that callback must not throw an exception
		/// if called when cancellation is requested otherwise std::terminate()
		/// will be called.
		///
		/// \throw std::bad_alloc
		/// If registration failed due to insufficient memory available.
		template<
			typename FUNC,
			typename = std::enable_if_t<std::is_constructible_v<std::function<void()>, FUNC&&>>>
		cancellation_registration(cancellation_token token, FUNC&& callback)
			: m_callback(std::forward<FUNC>(callback))
		{
			register_callback(std::move(token));
		}

		cancellation_registration(const cancellation_registration& other) = delete;
		cancellation_registration& operator=(const cancellation_registration& other) = delete;

		/// Deregisters the callback.
		///
		/// After the destructor returns it is guaranteed that the callback
		/// will not be subsequently called during a call to request_cancellation()
		/// on the cancellation_source.
		///
		/// This may block if cancellation has been requested on another thread
		/// is it will need to wait until this callback has finished executing
		/// before the callback can be destroyed.
		~cancellation_registration();

	private:

		friend class detail::cancellation_state;
		friend struct detail::cancellation_registration_state;

		void register_callback(cancellation_token&& token);

		detail::cancellation_state* m_state;
		std::function<void()> m_callback;
		detail::cancellation_registration_list_chunk* m_chunk;
		std::uint32_t m_entryIndex;
	};
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

# include <atomic>
# include <optional>
# include <experimental/coroutine>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_accept_operation_impl
		{
		public:

			socket_accept_operation_impl(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_listeningSocket(listeningSocket)
				, m_acceptingSocket(acceptingSocket)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

#if CPPCORO_COMPILER_MSVC
# pragma warning(push)
# pragma warning(disable : 4324) // Structure padded due to alignment
#endif

			socket& m_listeningSocket;
			socket& m_acceptingSocket;
			alignas(8) std::uint8_t m_addressBuffer[88];

#if CPPCORO_COMPILER_MSVC
# pragma warning(pop)
#endif

		};

		class socket_accept_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_accept_operation>
		{
		public:

			socket_accept_operation(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_accept_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};

		class socket_accept_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>
		{
		public:

			socket_accept_operation_cancellable(
				socket& listeningSocket,
				socket& acceptingSocket,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>(std::move(ct))
				, m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_CONNECT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_CONNECT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED

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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_address
		{
		public:

			// Constructs to IPv4 address 0.0.0.0
			ip_address() noexcept;

			ip_address(ipv4_address address) noexcept;
			ip_address(ipv6_address address) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_address& to_ipv4() const;
			const ipv6_address& to_ipv6() const;

			const std::uint8_t* bytes() const noexcept;

			std::string to_string() const;

			static std::optional<ip_address> from_string(std::string_view string) noexcept;

			bool operator==(const ip_address& rhs) const noexcept;
			bool operator!=(const ip_address& rhs) const noexcept;

			//  ipv4_address sorts less than ipv6_address
			bool operator<(const ip_address& rhs) const noexcept;
			bool operator>(const ip_address& rhs) const noexcept;
			bool operator<=(const ip_address& rhs) const noexcept;
			bool operator>=(const ip_address& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_address m_ipv4;
				ipv6_address m_ipv6;
			};

		};

		inline ip_address::ip_address() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_address::ip_address(ipv4_address address) noexcept
			: m_family(family::ipv4)
			, m_ipv4(address)
		{}

		inline ip_address::ip_address(ipv6_address address) noexcept
			: m_family(family::ipv6)
			, m_ipv6(address)
		{
		}

		inline const ipv4_address& ip_address::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_address& ip_address::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline const std::uint8_t* ip_address::bytes() const noexcept
		{
			return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
		}

		inline bool ip_address::operator==(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator!=(const ip_address& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_address::operator<(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator>(const ip_address& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_address::operator<=(const ip_address& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_address::operator>=(const ip_address& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_endpoint
		{
		public:

			// Constructs to IPv4 end-point 0.0.0.0:0
			ip_endpoint() noexcept;

			ip_endpoint(ipv4_endpoint endpoint) noexcept;
			ip_endpoint(ipv6_endpoint endpoint) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_endpoint& to_ipv4() const;
			const ipv6_endpoint& to_ipv6() const;

			ip_address address() const noexcept;
			std::uint16_t port() const noexcept;

			std::string to_string() const;

			static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

			bool operator==(const ip_endpoint& rhs) const noexcept;
			bool operator!=(const ip_endpoint& rhs) const noexcept;

			//  ipv4_endpoint sorts less than ipv6_endpoint
			bool operator<(const ip_endpoint& rhs) const noexcept;
			bool operator>(const ip_endpoint& rhs) const noexcept;
			bool operator<=(const ip_endpoint& rhs) const noexcept;
			bool operator>=(const ip_endpoint& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_endpoint m_ipv4;
				ipv6_endpoint m_ipv6;
			};

		};

		inline ip_endpoint::ip_endpoint() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
			: m_family(family::ipv4)
			, m_ipv4(endpoint)
		{}

		inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
			: m_family(family::ipv6)
			, m_ipv6(endpoint)
		{
		}

		inline const ipv4_endpoint& ip_endpoint::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_endpoint& ip_endpoint::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline ip_address ip_endpoint::address() const noexcept
		{
			if (is_ipv4())
			{
				return m_ipv4.address();
			}
			else
			{
				return m_ipv6.address();
			}
		}

		inline std::uint16_t ip_endpoint::port() const noexcept
		{
			return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
		}

		inline bool ip_endpoint::operator==(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator!=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_endpoint::operator<(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator>(const ip_endpoint& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_endpoint::operator<=(const ip_endpoint& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_endpoint::operator>=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_connect_operation_impl
		{
		public:

			socket_connect_operation_impl(
				socket& socket,
				const ip_endpoint& remoteEndPoint) noexcept
				: m_socket(socket)
				, m_remoteEndPoint(remoteEndPoint)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

			socket& m_socket;
			ip_endpoint m_remoteEndPoint;

		};

		class socket_connect_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_connect_operation>
		{
		public:

			socket_connect_operation(
				socket& socket,
				const ip_endpoint& remoteEndPoint) noexcept
				: m_impl(socket, remoteEndPoint)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_connect_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			decltype(auto) get_result() { return m_impl.get_result(*this); }

			socket_connect_operation_impl m_impl;

		};

		class socket_connect_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>
		{
		public:

			socket_connect_operation_cancellable(
				socket& socket,
				const ip_endpoint& remoteEndPoint,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>(std::move(ct))
				, m_impl(socket, remoteEndPoint)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_connect_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_DISCONNECT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_DISCONNECT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_disconnect_operation_impl
		{
		public:

			socket_disconnect_operation_impl(socket& socket) noexcept
				: m_socket(socket)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

			socket& m_socket;

		};

		class socket_disconnect_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_disconnect_operation>
		{
		public:

			socket_disconnect_operation(socket& socket) noexcept
				: m_impl(socket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_disconnect_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_disconnect_operation_impl m_impl;

		};

		class socket_disconnect_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>
		{
		public:

			socket_disconnect_operation_cancellable(socket& socket, cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>(std::move(ct))
				, m_impl(socket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_disconnect_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_RECV_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_RECV_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <cstdint>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_recv_operation_impl
	{
	public:

		socket_recv_operation_impl(
			socket& s,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(s)
			, m_buffer(buffer, byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		socket& m_socket;
		cppcoro::detail::win32::wsabuf m_buffer;

	};

	class socket_recv_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_recv_operation>
	{
	public:

		socket_recv_operation(
			socket& s,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_recv_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		socket_recv_operation_impl m_impl;

	};

	class socket_recv_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>
	{
	public:

		socket_recv_operation_cancellable(
			socket& s,
			void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>(std::move(ct))
			, m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { m_impl.cancel(*this); }

		socket_recv_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_RECV_FROM_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_RECV_FROM_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED

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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_address
		{
		public:

			// Constructs to IPv4 address 0.0.0.0
			ip_address() noexcept;

			ip_address(ipv4_address address) noexcept;
			ip_address(ipv6_address address) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_address& to_ipv4() const;
			const ipv6_address& to_ipv6() const;

			const std::uint8_t* bytes() const noexcept;

			std::string to_string() const;

			static std::optional<ip_address> from_string(std::string_view string) noexcept;

			bool operator==(const ip_address& rhs) const noexcept;
			bool operator!=(const ip_address& rhs) const noexcept;

			//  ipv4_address sorts less than ipv6_address
			bool operator<(const ip_address& rhs) const noexcept;
			bool operator>(const ip_address& rhs) const noexcept;
			bool operator<=(const ip_address& rhs) const noexcept;
			bool operator>=(const ip_address& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_address m_ipv4;
				ipv6_address m_ipv6;
			};

		};

		inline ip_address::ip_address() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_address::ip_address(ipv4_address address) noexcept
			: m_family(family::ipv4)
			, m_ipv4(address)
		{}

		inline ip_address::ip_address(ipv6_address address) noexcept
			: m_family(family::ipv6)
			, m_ipv6(address)
		{
		}

		inline const ipv4_address& ip_address::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_address& ip_address::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline const std::uint8_t* ip_address::bytes() const noexcept
		{
			return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
		}

		inline bool ip_address::operator==(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator!=(const ip_address& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_address::operator<(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator>(const ip_address& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_address::operator<=(const ip_address& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_address::operator>=(const ip_address& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_endpoint
		{
		public:

			// Constructs to IPv4 end-point 0.0.0.0:0
			ip_endpoint() noexcept;

			ip_endpoint(ipv4_endpoint endpoint) noexcept;
			ip_endpoint(ipv6_endpoint endpoint) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_endpoint& to_ipv4() const;
			const ipv6_endpoint& to_ipv6() const;

			ip_address address() const noexcept;
			std::uint16_t port() const noexcept;

			std::string to_string() const;

			static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

			bool operator==(const ip_endpoint& rhs) const noexcept;
			bool operator!=(const ip_endpoint& rhs) const noexcept;

			//  ipv4_endpoint sorts less than ipv6_endpoint
			bool operator<(const ip_endpoint& rhs) const noexcept;
			bool operator>(const ip_endpoint& rhs) const noexcept;
			bool operator<=(const ip_endpoint& rhs) const noexcept;
			bool operator>=(const ip_endpoint& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_endpoint m_ipv4;
				ipv6_endpoint m_ipv6;
			};

		};

		inline ip_endpoint::ip_endpoint() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
			: m_family(family::ipv4)
			, m_ipv4(endpoint)
		{}

		inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
			: m_family(family::ipv6)
			, m_ipv6(endpoint)
		{
		}

		inline const ipv4_endpoint& ip_endpoint::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_endpoint& ip_endpoint::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline ip_address ip_endpoint::address() const noexcept
		{
			if (is_ipv4())
			{
				return m_ipv4.address();
			}
			else
			{
				return m_ipv6.address();
			}
		}

		inline std::uint16_t ip_endpoint::port() const noexcept
		{
			return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
		}

		inline bool ip_endpoint::operator==(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator!=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_endpoint::operator<(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator>(const ip_endpoint& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_endpoint::operator<=(const ip_endpoint& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_endpoint::operator>=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif

#include <cstdint>
#include <tuple>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_recv_from_operation_impl
	{
	public:

		socket_recv_from_operation_impl(
			socket& socket,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(socket)
			, m_buffer(buffer, byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		std::tuple<std::size_t, ip_endpoint> get_result(
			cppcoro::detail::win32_overlapped_operation_base& operation);

	private:

		socket& m_socket;
		cppcoro::detail::win32::wsabuf m_buffer;

		static constexpr std::size_t sockaddrStorageAlignment = 4;

		// Storage suitable for either SOCKADDR_IN or SOCKADDR_IN6
		alignas(sockaddrStorageAlignment) std::uint8_t m_sourceSockaddrStorage[28];
		int m_sourceSockaddrLength;

	};

	class socket_recv_from_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_recv_from_operation>
	{
	public:

		socket_recv_from_operation(
			socket& socket,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(socket, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_recv_from_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		decltype(auto) get_result() { return m_impl.get_result(*this); }

		socket_recv_from_operation_impl m_impl;

	};

	class socket_recv_from_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_from_operation_cancellable>
	{
	public:

		socket_recv_from_operation_cancellable(
			socket& socket,
			void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_from_operation_cancellable>(std::move(ct))
			, m_impl(socket, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_from_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { m_impl.cancel(*this); }
		decltype(auto) get_result() { return m_impl.get_result(*this); }

		socket_recv_from_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_SEND_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_SEND_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <cstdint>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_send_operation_impl
	{
	public:

		socket_send_operation_impl(
			socket& s,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(s)
			, m_buffer(const_cast<void*>(buffer), byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		socket& m_socket;
		cppcoro::detail::win32::wsabuf m_buffer;

	};

	class socket_send_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_send_operation>
	{
	public:

		socket_send_operation(
			socket& s,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_send_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		socket_send_operation_impl m_impl;

	};

	class socket_send_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>
	{
	public:

		socket_send_operation_cancellable(
			socket& s,
			const void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>(std::move(ct))
			, m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { return m_impl.cancel(*this); }

		socket_send_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_SEND_TO_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_SEND_TO_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED

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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_address
		{
		public:

			// Constructs to IPv4 address 0.0.0.0
			ip_address() noexcept;

			ip_address(ipv4_address address) noexcept;
			ip_address(ipv6_address address) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_address& to_ipv4() const;
			const ipv6_address& to_ipv6() const;

			const std::uint8_t* bytes() const noexcept;

			std::string to_string() const;

			static std::optional<ip_address> from_string(std::string_view string) noexcept;

			bool operator==(const ip_address& rhs) const noexcept;
			bool operator!=(const ip_address& rhs) const noexcept;

			//  ipv4_address sorts less than ipv6_address
			bool operator<(const ip_address& rhs) const noexcept;
			bool operator>(const ip_address& rhs) const noexcept;
			bool operator<=(const ip_address& rhs) const noexcept;
			bool operator>=(const ip_address& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_address m_ipv4;
				ipv6_address m_ipv6;
			};

		};

		inline ip_address::ip_address() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_address::ip_address(ipv4_address address) noexcept
			: m_family(family::ipv4)
			, m_ipv4(address)
		{}

		inline ip_address::ip_address(ipv6_address address) noexcept
			: m_family(family::ipv6)
			, m_ipv6(address)
		{
		}

		inline const ipv4_address& ip_address::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_address& ip_address::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline const std::uint8_t* ip_address::bytes() const noexcept
		{
			return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
		}

		inline bool ip_address::operator==(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator!=(const ip_address& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_address::operator<(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator>(const ip_address& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_address::operator<=(const ip_address& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_address::operator>=(const ip_address& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_endpoint
		{
		public:

			// Constructs to IPv4 end-point 0.0.0.0:0
			ip_endpoint() noexcept;

			ip_endpoint(ipv4_endpoint endpoint) noexcept;
			ip_endpoint(ipv6_endpoint endpoint) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_endpoint& to_ipv4() const;
			const ipv6_endpoint& to_ipv6() const;

			ip_address address() const noexcept;
			std::uint16_t port() const noexcept;

			std::string to_string() const;

			static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

			bool operator==(const ip_endpoint& rhs) const noexcept;
			bool operator!=(const ip_endpoint& rhs) const noexcept;

			//  ipv4_endpoint sorts less than ipv6_endpoint
			bool operator<(const ip_endpoint& rhs) const noexcept;
			bool operator>(const ip_endpoint& rhs) const noexcept;
			bool operator<=(const ip_endpoint& rhs) const noexcept;
			bool operator>=(const ip_endpoint& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_endpoint m_ipv4;
				ipv6_endpoint m_ipv6;
			};

		};

		inline ip_endpoint::ip_endpoint() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
			: m_family(family::ipv4)
			, m_ipv4(endpoint)
		{}

		inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
			: m_family(family::ipv6)
			, m_ipv6(endpoint)
		{
		}

		inline const ipv4_endpoint& ip_endpoint::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_endpoint& ip_endpoint::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline ip_address ip_endpoint::address() const noexcept
		{
			if (is_ipv4())
			{
				return m_ipv4.address();
			}
			else
			{
				return m_ipv6.address();
			}
		}

		inline std::uint16_t ip_endpoint::port() const noexcept
		{
			return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
		}

		inline bool ip_endpoint::operator==(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator!=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_endpoint::operator<(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator>(const ip_endpoint& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_endpoint::operator<=(const ip_endpoint& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_endpoint::operator>=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif

#include <cstdint>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_send_to_operation_impl
	{
	public:

		socket_send_to_operation_impl(
			socket& s,
			const ip_endpoint& destination,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(s)
			, m_destination(destination)
			, m_buffer(const_cast<void*>(buffer), byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		socket& m_socket;
		ip_endpoint m_destination;
		cppcoro::detail::win32::wsabuf m_buffer;

	};

	class socket_send_to_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_send_to_operation>
	{
	public:

		socket_send_to_operation(
			socket& s,
			const ip_endpoint& destination,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(s, destination, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_send_to_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		socket_send_to_operation_impl m_impl;

	};

	class socket_send_to_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_to_operation_cancellable>
	{
	public:

		socket_send_to_operation_cancellable(
			socket& s,
			const ip_endpoint& destination,
			const void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_to_operation_cancellable>(std::move(ct))
			, m_impl(s, destination, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_to_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { return m_impl.cancel(*this); }

		socket_send_to_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
#endif

namespace cppcoro
{
	class io_service;

	namespace net
	{
		class socket
		{
		public:

			/// Create a socket that can be used to communicate using TCP/IPv4 protocol.
			///
			/// \param ioSvc
			/// The I/O service the socket will use for dispatching I/O completion events.
			///
			/// \return
			/// The newly created socket.
			///
			/// \throws std::system_error
			/// If the socket could not be created for some reason.
			static socket create_tcpv4(io_service& ioSvc);

			/// Create a socket that can be used to communicate using TCP/IPv6 protocol.
			///
			/// \param ioSvc
			/// The I/O service the socket will use for dispatching I/O completion events.
			///
			/// \return
			/// The newly created socket.
			///
			/// \throws std::system_error
			/// If the socket could not be created for some reason.
			static socket create_tcpv6(io_service& ioSvc);

			/// Create a socket that can be used to communicate using UDP/IPv4 protocol.
			///
			/// \param ioSvc
			/// The I/O service the socket will use for dispatching I/O completion events.
			///
			/// \return
			/// The newly created socket.
			///
			/// \throws std::system_error
			/// If the socket could not be created for some reason.
			static socket create_udpv4(io_service& ioSvc);

			/// Create a socket that can be used to communicate using UDP/IPv6 protocol.
			///
			/// \param ioSvc
			/// The I/O service the socket will use for dispatching I/O completion events.
			///
			/// \return
			/// The newly created socket.
			///
			/// \throws std::system_error
			/// If the socket could not be created for some reason.
			static socket create_udpv6(io_service& ioSvc);

			socket(socket&& other) noexcept;

			/// Closes the socket, releasing any associated resources.
			///
			/// If the socket still has an open connection then the connection will be
			/// reset. The destructor will not block waiting for queueud data to be sent.
			/// If you need to ensure that queued data is delivered then you must call
			/// disconnect() and wait until the disconnect operation completes.
			~socket();

			socket& operator=(socket&& other) noexcept;

#if CPPCORO_OS_WINNT
			/// Get the Win32 socket handle assocaited with this socket.
			cppcoro::detail::win32::socket_t native_handle() noexcept { return m_handle; }

			/// Query whether I/O operations that complete synchronously will skip posting
			/// an I/O completion event to the I/O completion port.
			///
			/// The operation class implementations can use this to determine whether or not
			/// it should immediately resume the coroutine on the current thread upon an
			/// operation completing synchronously or whether it should suspend the coroutine
			/// and wait until the I/O completion event is dispatched to an I/O thread.
			bool skip_completion_on_success() noexcept { return m_skipCompletionOnSuccess; }
#endif

			/// Get the address and port of the local end-point.
			///
			/// If the socket is not bound then this will be the unspecified end-point
			/// of the socket's associated address-family.
			const ip_endpoint& local_endpoint() const noexcept { return m_localEndPoint; }

			/// Get the address and port of the remote end-point.
			///
			/// If the socket is not in the connected state then this will be the unspecified
			/// end-point of the socket's associated address-family.
			const ip_endpoint& remote_endpoint() const noexcept { return m_remoteEndPoint; }

			/// Bind the local end of this socket to the specified local end-point.
			///
			/// \param localEndPoint
			/// The end-point to bind to.
			/// This can be either an unspecified address (in which case it binds to all available
			/// interfaces) and/or an unspecified port (in which case a random port is allocated).
			///
			/// \throws std::system_error
			/// If the socket could not be bound for some reason.
			void bind(const ip_endpoint& localEndPoint);

			/// Put the socket into a passive listening state that will start acknowledging
			/// and queueing up new connections ready to be accepted by a call to 'accept()'.
			///
			/// The backlog of connections ready to be accepted will be set to some default
			/// suitable large value, depending on the network provider. If you need more
			/// control over the size of the queue then use the overload of listen()
			/// that accepts a 'backlog' parameter.
			///
			/// \throws std::system_error
			/// If the socket could not be placed into a listening mode.
			void listen();

			/// Put the socket into a passive listening state that will start acknowledging
			/// and queueing up new connections ready to be accepted by a call to 'accept()'.
			///
			/// \param backlog
			/// The maximum number of pending connections to allow in the queue of ready-to-accept
			/// connections.
			///
			/// \throws std::system_error
			/// If the socket could not be placed into a listening mode.
			void listen(std::uint32_t backlog);

			/// Connect the socket to the specified remote end-point.
			///
			/// The socket must be in a bound but unconnected state prior to this call.
			///
			/// \param remoteEndPoint
			/// The IP address and port-number to connect to.
			///
			/// \return
			/// An awaitable object that must be co_await'ed to perform the async connect
			/// operation. The result of the co_await expression is type void.
			[[nodiscard]]
			socket_connect_operation connect(const ip_endpoint& remoteEndPoint) noexcept;

			/// Connect to the specified remote end-point.
			///
			/// \param remoteEndPoint
			/// The IP address and port of the remote end-point to connect to.
			///
			/// \param ct
			/// A cancellation token that can be used to communicate a request to
			/// later cancel the operation. If the operation is successfully
			/// cancelled then it will complete by throwing a cppcoro::operation_cancelled
			/// exception.
			///
			/// \return
			/// An awaitable object that will start the connect operation when co_await'ed
			/// and will suspend the coroutine, resuming it when the operation completes.
			/// The result of the co_await expression has type 'void'.
			[[nodiscard]]
			socket_connect_operation_cancellable connect(
				const ip_endpoint& remoteEndPoint,
				cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_accept_operation accept(socket& acceptingSocket) noexcept;
			[[nodiscard]]
			socket_accept_operation_cancellable accept(
				socket& acceptingSocket,
				cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_disconnect_operation disconnect() noexcept;
			[[nodiscard]]
			socket_disconnect_operation_cancellable disconnect(cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_send_operation send(
				const void* buffer,
				std::size_t size) noexcept;
			[[nodiscard]]
			socket_send_operation_cancellable send(
				const void* buffer,
				std::size_t size,
				cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_recv_operation recv(
				void* buffer,
				std::size_t size) noexcept;
			[[nodiscard]]
			socket_recv_operation_cancellable recv(
				void* buffer,
				std::size_t size,
				cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_recv_from_operation recv_from(
				void* buffer,
				std::size_t size) noexcept;
			[[nodiscard]]
			socket_recv_from_operation_cancellable recv_from(
				void* buffer,
				std::size_t size,
				cancellation_token ct) noexcept;

			[[nodiscard]]
			socket_send_to_operation send_to(
				const ip_endpoint& destination,
				const void* buffer,
				std::size_t size) noexcept;
			[[nodiscard]]
			socket_send_to_operation_cancellable send_to(
				const ip_endpoint& destination,
				const void* buffer,
				std::size_t size,
				cancellation_token ct) noexcept;

			void close_send();
			void close_recv();

		private:

			friend class socket_accept_operation_impl;
			friend class socket_connect_operation_impl;

#if CPPCORO_OS_WINNT
			explicit socket(
				cppcoro::detail::win32::socket_t handle,
				bool skipCompletionOnSuccess) noexcept;
#endif

#if CPPCORO_OS_WINNT
			cppcoro::detail::win32::socket_t m_handle;
			bool m_skipCompletionOnSuccess;
#endif

			ip_endpoint m_localEndPoint;
			ip_endpoint m_remoteEndPoint;

		};
	}
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_ACCEPT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED
#define CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <functional>
#include <utility>
#include <type_traits>
#include <atomic>

namespace cppcoro
{
	namespace detail
	{
		class cancellation_state;
		struct cancellation_registration_list_chunk;
		struct cancellation_registration_state;
	}

	class cancellation_registration
	{
	public:

		/// Registers the callback to be executed when cancellation is requested
		/// on the cancellation_token.
		///
		/// The callback will be executed if cancellation is requested for the
		/// specified cancellation token. If cancellation has already been requested
		/// then the callback will be executed immediately, before the constructor
		/// returns. If cancellation has not yet been requested then the callback
		/// will be executed on the first thread to request cancellation inside
		/// the call to cancellation_source::request_cancellation().
		///
		/// \param token
		/// The cancellation token to register the callback with.
		///
		/// \param callback
		/// The callback to be executed when cancellation is requested on the
		/// the cancellation_token. Note that callback must not throw an exception
		/// if called when cancellation is requested otherwise std::terminate()
		/// will be called.
		///
		/// \throw std::bad_alloc
		/// If registration failed due to insufficient memory available.
		template<
			typename FUNC,
			typename = std::enable_if_t<std::is_constructible_v<std::function<void()>, FUNC&&>>>
		cancellation_registration(cancellation_token token, FUNC&& callback)
			: m_callback(std::forward<FUNC>(callback))
		{
			register_callback(std::move(token));
		}

		cancellation_registration(const cancellation_registration& other) = delete;
		cancellation_registration& operator=(const cancellation_registration& other) = delete;

		/// Deregisters the callback.
		///
		/// After the destructor returns it is guaranteed that the callback
		/// will not be subsequently called during a call to request_cancellation()
		/// on the cancellation_source.
		///
		/// This may block if cancellation has been requested on another thread
		/// is it will need to wait until this callback has finished executing
		/// before the callback can be destroyed.
		~cancellation_registration();

	private:

		friend class detail::cancellation_state;
		friend struct detail::cancellation_registration_state;

		void register_callback(cancellation_token&& token);

		detail::cancellation_state* m_state;
		std::function<void()> m_callback;
		detail::cancellation_registration_list_chunk* m_chunk;
		std::uint32_t m_entryIndex;
	};
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

# include <atomic>
# include <optional>
# include <experimental/coroutine>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_accept_operation_impl
		{
		public:

			socket_accept_operation_impl(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_listeningSocket(listeningSocket)
				, m_acceptingSocket(acceptingSocket)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

#if CPPCORO_COMPILER_MSVC
# pragma warning(push)
# pragma warning(disable : 4324) // Structure padded due to alignment
#endif

			socket& m_listeningSocket;
			socket& m_acceptingSocket;
			alignas(8) std::uint8_t m_addressBuffer[88];

#if CPPCORO_COMPILER_MSVC
# pragma warning(pop)
#endif

		};

		class socket_accept_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_accept_operation>
		{
		public:

			socket_accept_operation(
				socket& listeningSocket,
				socket& acceptingSocket) noexcept
				: m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_accept_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};

		class socket_accept_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>
		{
		public:

			socket_accept_operation_cancellable(
				socket& listeningSocket,
				socket& acceptingSocket,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>(std::move(ct))
				, m_impl(listeningSocket, acceptingSocket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_accept_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_accept_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_CONNECT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_CONNECT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED
#define CPPCORO_NET_IP_ENDPOINT_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED
#define CPPCORO_NET_IP_ADDRESS_HPP_INCLUDED

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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_address
		{
		public:

			// Constructs to IPv4 address 0.0.0.0
			ip_address() noexcept;

			ip_address(ipv4_address address) noexcept;
			ip_address(ipv6_address address) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_address& to_ipv4() const;
			const ipv6_address& to_ipv6() const;

			const std::uint8_t* bytes() const noexcept;

			std::string to_string() const;

			static std::optional<ip_address> from_string(std::string_view string) noexcept;

			bool operator==(const ip_address& rhs) const noexcept;
			bool operator!=(const ip_address& rhs) const noexcept;

			//  ipv4_address sorts less than ipv6_address
			bool operator<(const ip_address& rhs) const noexcept;
			bool operator>(const ip_address& rhs) const noexcept;
			bool operator<=(const ip_address& rhs) const noexcept;
			bool operator>=(const ip_address& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_address m_ipv4;
				ipv6_address m_ipv6;
			};

		};

		inline ip_address::ip_address() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_address::ip_address(ipv4_address address) noexcept
			: m_family(family::ipv4)
			, m_ipv4(address)
		{}

		inline ip_address::ip_address(ipv6_address address) noexcept
			: m_family(family::ipv6)
			, m_ipv6(address)
		{
		}

		inline const ipv4_address& ip_address::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_address& ip_address::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline const std::uint8_t* ip_address::bytes() const noexcept
		{
			return is_ipv4() ? m_ipv4.bytes() : m_ipv6.bytes();
		}

		inline bool ip_address::operator==(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator!=(const ip_address& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_address::operator<(const ip_address& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_address::operator>(const ip_address& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_address::operator<=(const ip_address& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_address::operator>=(const ip_address& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif
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

#include <cassert>
#include <optional>
#include <string>

namespace cppcoro
{
	namespace net
	{
		class ip_endpoint
		{
		public:

			// Constructs to IPv4 end-point 0.0.0.0:0
			ip_endpoint() noexcept;

			ip_endpoint(ipv4_endpoint endpoint) noexcept;
			ip_endpoint(ipv6_endpoint endpoint) noexcept;

			bool is_ipv4() const noexcept { return m_family == family::ipv4; }
			bool is_ipv6() const noexcept { return m_family == family::ipv6; }

			const ipv4_endpoint& to_ipv4() const;
			const ipv6_endpoint& to_ipv6() const;

			ip_address address() const noexcept;
			std::uint16_t port() const noexcept;

			std::string to_string() const;

			static std::optional<ip_endpoint> from_string(std::string_view string) noexcept;

			bool operator==(const ip_endpoint& rhs) const noexcept;
			bool operator!=(const ip_endpoint& rhs) const noexcept;

			//  ipv4_endpoint sorts less than ipv6_endpoint
			bool operator<(const ip_endpoint& rhs) const noexcept;
			bool operator>(const ip_endpoint& rhs) const noexcept;
			bool operator<=(const ip_endpoint& rhs) const noexcept;
			bool operator>=(const ip_endpoint& rhs) const noexcept;

		private:

			enum class family
			{
				ipv4,
				ipv6
			};

			family m_family;

			union
			{
				ipv4_endpoint m_ipv4;
				ipv6_endpoint m_ipv6;
			};

		};

		inline ip_endpoint::ip_endpoint() noexcept
			: m_family(family::ipv4)
			, m_ipv4()
		{}

		inline ip_endpoint::ip_endpoint(ipv4_endpoint endpoint) noexcept
			: m_family(family::ipv4)
			, m_ipv4(endpoint)
		{}

		inline ip_endpoint::ip_endpoint(ipv6_endpoint endpoint) noexcept
			: m_family(family::ipv6)
			, m_ipv6(endpoint)
		{
		}

		inline const ipv4_endpoint& ip_endpoint::to_ipv4() const
		{
			assert(is_ipv4());
			return m_ipv4;
		}

		inline const ipv6_endpoint& ip_endpoint::to_ipv6() const
		{
			assert(is_ipv6());
			return m_ipv6;
		}

		inline ip_address ip_endpoint::address() const noexcept
		{
			if (is_ipv4())
			{
				return m_ipv4.address();
			}
			else
			{
				return m_ipv6.address();
			}
		}

		inline std::uint16_t ip_endpoint::port() const noexcept
		{
			return is_ipv4() ? m_ipv4.port() : m_ipv6.port();
		}

		inline bool ip_endpoint::operator==(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return rhs.is_ipv4() && m_ipv4 == rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 == rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator!=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this == rhs);
		}

		inline bool ip_endpoint::operator<(const ip_endpoint& rhs) const noexcept
		{
			if (is_ipv4())
			{
				return !rhs.is_ipv4() || m_ipv4 < rhs.m_ipv4;
			}
			else
			{
				return rhs.is_ipv6() && m_ipv6 < rhs.m_ipv6;
			}
		}

		inline bool ip_endpoint::operator>(const ip_endpoint& rhs) const noexcept
		{
			return rhs < *this;
		}

		inline bool ip_endpoint::operator<=(const ip_endpoint& rhs) const noexcept
		{
			return !(rhs < *this);
		}

		inline bool ip_endpoint::operator>=(const ip_endpoint& rhs) const noexcept
		{
			return !(*this < rhs);
		}
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_connect_operation_impl
		{
		public:

			socket_connect_operation_impl(
				socket& socket,
				const ip_endpoint& remoteEndPoint) noexcept
				: m_socket(socket)
				, m_remoteEndPoint(remoteEndPoint)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

			socket& m_socket;
			ip_endpoint m_remoteEndPoint;

		};

		class socket_connect_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_connect_operation>
		{
		public:

			socket_connect_operation(
				socket& socket,
				const ip_endpoint& remoteEndPoint) noexcept
				: m_impl(socket, remoteEndPoint)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_connect_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			decltype(auto) get_result() { return m_impl.get_result(*this); }

			socket_connect_operation_impl m_impl;

		};

		class socket_connect_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>
		{
		public:

			socket_connect_operation_cancellable(
				socket& socket,
				const ip_endpoint& remoteEndPoint,
				cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>(std::move(ct))
				, m_impl(socket, remoteEndPoint)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_connect_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_connect_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_DISCONNECT_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_DISCONNECT_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro
{
	namespace net
	{
		class socket;

		class socket_disconnect_operation_impl
		{
		public:

			socket_disconnect_operation_impl(socket& socket) noexcept
				: m_socket(socket)
			{}

			bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
			void get_result(cppcoro::detail::win32_overlapped_operation_base& operation);

		private:

			socket& m_socket;

		};

		class socket_disconnect_operation
			: public cppcoro::detail::win32_overlapped_operation<socket_disconnect_operation>
		{
		public:

			socket_disconnect_operation(socket& socket) noexcept
				: m_impl(socket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation<socket_disconnect_operation>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_disconnect_operation_impl m_impl;

		};

		class socket_disconnect_operation_cancellable
			: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>
		{
		public:

			socket_disconnect_operation_cancellable(socket& socket, cancellation_token&& ct) noexcept
				: cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>(std::move(ct))
				, m_impl(socket)
			{}

		private:

			friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_disconnect_operation_cancellable>;

			bool try_start() noexcept { return m_impl.try_start(*this); }
			void cancel() noexcept { m_impl.cancel(*this); }
			void get_result() { m_impl.get_result(*this); }

			socket_disconnect_operation_impl m_impl;

		};
	}
}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_RECV_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_RECV_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <cstdint>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_recv_operation_impl
	{
	public:

		socket_recv_operation_impl(
			socket& s,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(s)
			, m_buffer(buffer, byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		socket& m_socket;
		cppcoro::detail::win32::wsabuf m_buffer;

	};

	class socket_recv_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_recv_operation>
	{
	public:

		socket_recv_operation(
			socket& s,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_recv_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		socket_recv_operation_impl m_impl;

	};

	class socket_recv_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>
	{
	public:

		socket_recv_operation_cancellable(
			socket& s,
			void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>(std::move(ct))
			, m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_recv_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { m_impl.cancel(*this); }

		socket_recv_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_NET_SOCKET_SEND_OPERATION_HPP_INCLUDED
#define CPPCORO_NET_SOCKET_SEND_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <cstdint>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro::net
{
	class socket;

	class socket_send_operation_impl
	{
	public:

		socket_send_operation_impl(
			socket& s,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_socket(s)
			, m_buffer(const_cast<void*>(buffer), byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		socket& m_socket;
		cppcoro::detail::win32::wsabuf m_buffer;

	};

	class socket_send_operation
		: public cppcoro::detail::win32_overlapped_operation<socket_send_operation>
	{
	public:

		socket_send_operation(
			socket& s,
			const void* buffer,
			std::size_t byteCount) noexcept
			: m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<socket_send_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		socket_send_operation_impl m_impl;

	};

	class socket_send_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>
	{
	public:

		socket_send_operation_cancellable(
			socket& s,
			const void* buffer,
			std::size_t byteCount,
			cancellation_token&& ct) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>(std::move(ct))
			, m_impl(s, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<socket_send_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { return m_impl.cancel(*this); }

		socket_send_operation_impl m_impl;

	};

}

#endif // CPPCORO_OS_WINNT

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_IO_SERVICE_HPP_INCLUDED
#define CPPCORO_IO_SERVICE_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED
#define CPPCORO_CANCELLATION_REGISTRATION_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED
#define CPPCORO_CANCELLATION_TOKEN_HPP_INCLUDED

namespace cppcoro
{
	class cancellation_source;
	class cancellation_registration;

	namespace detail
	{
		class cancellation_state;
	}

	class cancellation_token
	{
	public:

		/// Construct to a cancellation token that can't be cancelled.
		cancellation_token() noexcept;

		/// Copy another cancellation token.
		///
		/// New token will refer to the same underlying state.
		cancellation_token(const cancellation_token& other) noexcept;

		cancellation_token(cancellation_token&& other) noexcept;

		~cancellation_token();

		cancellation_token& operator=(const cancellation_token& other) noexcept;

		cancellation_token& operator=(cancellation_token&& other) noexcept;

		void swap(cancellation_token& other) noexcept;

		/// Query if it is possible that this operation will be cancelled
		/// or not.
		///
		/// Cancellable operations may be able to take more efficient code-paths
		/// if they don't need to handle cancellation requests.
		bool can_be_cancelled() const noexcept;

		/// Query if some thread has requested cancellation on an associated
		/// cancellation_source object.
		bool is_cancellation_requested() const noexcept;

		/// Throws cppcoro::operation_cancelled exception if cancellation
		/// has been requested for the associated operation.
		void throw_if_cancellation_requested() const;

	private:

		friend class cancellation_source;
		friend class cancellation_registration;

		cancellation_token(detail::cancellation_state* state) noexcept;

		detail::cancellation_state* m_state;

	};

	inline void swap(cancellation_token& a, cancellation_token& b) noexcept
	{
		a.swap(b);
	}
}

#endif

#include <functional>
#include <utility>
#include <type_traits>
#include <atomic>

namespace cppcoro
{
	namespace detail
	{
		class cancellation_state;
		struct cancellation_registration_list_chunk;
		struct cancellation_registration_state;
	}

	class cancellation_registration
	{
	public:

		/// Registers the callback to be executed when cancellation is requested
		/// on the cancellation_token.
		///
		/// The callback will be executed if cancellation is requested for the
		/// specified cancellation token. If cancellation has already been requested
		/// then the callback will be executed immediately, before the constructor
		/// returns. If cancellation has not yet been requested then the callback
		/// will be executed on the first thread to request cancellation inside
		/// the call to cancellation_source::request_cancellation().
		///
		/// \param token
		/// The cancellation token to register the callback with.
		///
		/// \param callback
		/// The callback to be executed when cancellation is requested on the
		/// the cancellation_token. Note that callback must not throw an exception
		/// if called when cancellation is requested otherwise std::terminate()
		/// will be called.
		///
		/// \throw std::bad_alloc
		/// If registration failed due to insufficient memory available.
		template<
			typename FUNC,
			typename = std::enable_if_t<std::is_constructible_v<std::function<void()>, FUNC&&>>>
		cancellation_registration(cancellation_token token, FUNC&& callback)
			: m_callback(std::forward<FUNC>(callback))
		{
			register_callback(std::move(token));
		}

		cancellation_registration(const cancellation_registration& other) = delete;
		cancellation_registration& operator=(const cancellation_registration& other) = delete;

		/// Deregisters the callback.
		///
		/// After the destructor returns it is guaranteed that the callback
		/// will not be subsequently called during a call to request_cancellation()
		/// on the cancellation_source.
		///
		/// This may block if cancellation has been requested on another thread
		/// is it will need to wait until this callback has finished executing
		/// before the callback can be destroyed.
		~cancellation_registration();

	private:

		friend class detail::cancellation_state;
		friend struct detail::cancellation_registration_state;

		void register_callback(cancellation_token&& token);

		detail::cancellation_state* m_state;
		std::function<void()> m_callback;
		detail::cancellation_registration_list_chunk* m_chunk;
		std::uint32_t m_entryIndex;
	};
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
#endif

#include <optional>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <utility>
#include <mutex>
#include <coroutine>

namespace cppcoro
{
	class io_service
	{
	public:

		class schedule_operation;
		class timed_schedule_operation;

		/// Initialises the io_service.
		///
		/// Does not set a concurrency hint. All threads that enter the
		/// event loop will actively process events.
		io_service();

		/// Initialise the io_service with a concurrency hint.
		///
		/// \param concurrencyHint
		/// Specifies the target maximum number of I/O threads to be
		/// actively processing events.
		/// Note that the number of active threads may temporarily go
		/// above this number.
		io_service(std::uint32_t concurrencyHint);

		~io_service();

		io_service(io_service&& other) = delete;
		io_service(const io_service& other) = delete;
		io_service& operator=(io_service&& other) = delete;
		io_service& operator=(const io_service& other) = delete;

		/// Returns an operation that when awaited suspends the awaiting
		/// coroutine and reschedules it for resumption on an I/O thread
		/// associated with this io_service.
		[[nodiscard]]
		schedule_operation schedule() noexcept;

		/// Returns an operation that when awaited will suspend the
		/// awaiting coroutine for the specified delay. Once the delay
		/// has elapsed, the coroutine will resume execution on an
		/// I/O thread associated with this io_service.
		///
		/// \param delay
		/// The amount of time to delay scheduling resumption of the coroutine
		/// on an I/O thread. There is no guarantee that the coroutine will
		/// be resumed exactly after this delay.
		///
		/// \param cancellationToken [optional]
		/// A cancellation token that can be used to communicate a request to
		/// cancel the delayed schedule operation and schedule it for resumption
		/// immediately.
		/// The co_await operation will throw cppcoro::operation_cancelled if
		/// cancellation was requested before the coroutine could be resumed.
		template<typename REP, typename PERIOD>
		[[nodiscard]]
		timed_schedule_operation schedule_after(
			const std::chrono::duration<REP, PERIOD>& delay,
			cancellation_token cancellationToken = {}) noexcept;

		/// Process events until the io_service is stopped.
		///
		/// \return
		/// The number of events processed during this call.
		std::uint64_t process_events();

		/// Process events until either the io_service is stopped or
		/// there are no more pending events in the queue.
		///
		/// \return
		/// The number of events processed during this call.
		std::uint64_t process_pending_events();

		/// Block until either one event is processed or the io_service is stopped.
		///
		/// \return
		/// The number of events processed during this call.
		/// This will either be 0 or 1.
		std::uint64_t process_one_event();

		/// Process one event if there are any events pending, otherwise if there
		/// are no events pending or the io_service is stopped then return immediately.
		///
		/// \return
		/// The number of events processed during this call.
		/// This will either be 0 or 1.
		std::uint64_t process_one_pending_event();

		/// Shut down the io_service.
		///
		/// This will cause any threads currently in a call to one of the process_xxx() methods
		/// to return from that call once they finish processing the current event.
		///
		/// This call does not wait until all threads have exited the event loop so you
		/// must use other synchronisation mechanisms to wait for those threads.
		void stop() noexcept;

		/// Reset an io_service to prepare it for resuming processing of events.
		///
		/// Call this after a call to stop() to allow calls to process_xxx() methods
		/// to process events.
		///
		/// After calling stop() you should ensure that all threads have returned from
		/// calls to process_xxx() methods before calling reset().
		void reset();

		bool is_stop_requested() const noexcept;

		void notify_work_started() noexcept;

		void notify_work_finished() noexcept;

#if CPPCORO_OS_WINNT
		detail::win32::handle_t native_iocp_handle() noexcept;
		void ensure_winsock_initialised();
#endif

	private:

		class timer_thread_state;
		class timer_queue;

		friend class schedule_operation;
		friend class timed_schedule_operation;

		void schedule_impl(schedule_operation* operation) noexcept;

		void try_reschedule_overflow_operations() noexcept;

		bool try_enter_event_loop() noexcept;
		void exit_event_loop() noexcept;

		bool try_process_one_event(bool waitForEvent);

		void post_wake_up_event() noexcept;

		timer_thread_state* ensure_timer_thread_started();

		static constexpr std::uint32_t stop_requested_flag = 1;
		static constexpr std::uint32_t active_thread_count_increment = 2;

		// Bit 0: stop_requested_flag
		// Bit 1-31: count of active threads currently running the event loop
		std::atomic<std::uint32_t> m_threadState;

		std::atomic<std::uint32_t> m_workCount;

#if CPPCORO_OS_WINNT
		detail::win32::safe_handle m_iocpHandle;

		std::atomic<bool> m_winsockInitialised;
		std::mutex m_winsockInitialisationMutex;
#endif

		// Head of a linked-list of schedule operations that are
		// ready to run but that failed to be queued to the I/O
		// completion port (eg. due to low memory).
		std::atomic<schedule_operation*> m_scheduleOperations;

		std::atomic<timer_thread_state*> m_timerState;

	};

	class io_service::schedule_operation
	{
	public:

		schedule_operation(io_service& service) noexcept
			: m_service(service)
		{}

		bool await_ready() const noexcept { return false; }
		void await_suspend(std::coroutine_handle<> awaiter) noexcept;
		void await_resume() const noexcept {}

	private:

		friend class io_service;
		friend class io_service::timed_schedule_operation;

		io_service& m_service;
		std::coroutine_handle<> m_awaiter;
		schedule_operation* m_next;

	};

	class io_service::timed_schedule_operation
	{
	public:

		timed_schedule_operation(
			io_service& service,
			std::chrono::high_resolution_clock::time_point resumeTime,
			cppcoro::cancellation_token cancellationToken) noexcept;

		timed_schedule_operation(timed_schedule_operation&& other) noexcept;

		~timed_schedule_operation();

		timed_schedule_operation& operator=(timed_schedule_operation&& other) = delete;
		timed_schedule_operation(const timed_schedule_operation& other) = delete;
		timed_schedule_operation& operator=(const timed_schedule_operation& other) = delete;

		bool await_ready() const noexcept;
		void await_suspend(std::coroutine_handle<> awaiter);
		void await_resume();

	private:

		friend class io_service::timer_queue;
		friend class io_service::timer_thread_state;

		io_service::schedule_operation m_scheduleOperation;
		std::chrono::high_resolution_clock::time_point m_resumeTime;

		cppcoro::cancellation_token m_cancellationToken;
		std::optional<cppcoro::cancellation_registration> m_cancellationRegistration;

		timed_schedule_operation* m_next;

		std::atomic<std::uint32_t> m_refCount;

	};

	class io_work_scope
	{
	public:

		explicit io_work_scope(io_service& service) noexcept
			: m_service(&service)
		{
			service.notify_work_started();
		}

		io_work_scope(const io_work_scope& other) noexcept
			: m_service(other.m_service)
		{
			if (m_service != nullptr)
			{
				m_service->notify_work_started();
			}
		}

		io_work_scope(io_work_scope&& other) noexcept
			: m_service(other.m_service)
		{
			other.m_service = nullptr;
		}

		~io_work_scope()
		{
			if (m_service != nullptr)
			{
				m_service->notify_work_finished();
			}
		}

		void swap(io_work_scope& other) noexcept
		{
			std::swap(m_service, other.m_service);
		}

		io_work_scope& operator=(io_work_scope other) noexcept
		{
			swap(other);
			return *this;
		}

		io_service& service() noexcept
		{
			return *m_service;
		}

	private:

		io_service* m_service;

	};

	inline void swap(io_work_scope& a, io_work_scope& b)
	{
		a.swap(b);
	}
}

template<typename REP, typename RATIO>
cppcoro::io_service::timed_schedule_operation
cppcoro::io_service::schedule_after(
	const std::chrono::duration<REP, RATIO>& duration,
	cppcoro::cancellation_token cancellationToken) noexcept
{
	return timed_schedule_operation{
		*this,
		std::chrono::high_resolution_clock::now() + duration,
		std::move(cancellationToken)
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_ON_SCOPE_EXIT_HPP_INCLUDED
#define CPPCORO_ON_SCOPE_EXIT_HPP_INCLUDED

#include <type_traits>
#include <exception>

namespace cppcoro
{
	template<typename FUNC>
	class scoped_lambda
	{
	public:

		scoped_lambda(FUNC&& func)
			: m_func(std::forward<FUNC>(func))
			, m_cancelled(false)
		{}

		scoped_lambda(const scoped_lambda& other) = delete;

		scoped_lambda(scoped_lambda&& other)
			: m_func(std::forward<FUNC>(other.m_func))
			, m_cancelled(other.m_cancelled)
		{
			other.cancel();
		}

		~scoped_lambda()
		{
			if (!m_cancelled)
			{
				m_func();
			}
		}

		void cancel()
		{
			m_cancelled = true;
		}

		void call_now()
		{
			m_cancelled = true;
			m_func();
		}

	private:

		FUNC m_func;
		bool m_cancelled;

	};

	/// A scoped lambda that executes the lambda when the object destructs
	/// but only if exiting due to an exception (CALL_ON_FAILURE = true) or
	/// only if not exiting due to an exception (CALL_ON_FAILURE = false).
	template<typename FUNC, bool CALL_ON_FAILURE>
	class conditional_scoped_lambda
	{
	public:

		conditional_scoped_lambda(FUNC&& func)
			: m_func(std::forward<FUNC>(func))
			, m_uncaughtExceptionCount(std::uncaught_exceptions())
			, m_cancelled(false)
		{}

		conditional_scoped_lambda(const conditional_scoped_lambda& other) = delete;

		conditional_scoped_lambda(conditional_scoped_lambda&& other)
			noexcept(std::is_nothrow_move_constructible<FUNC>::value)
			: m_func(std::forward<FUNC>(other.m_func))
			, m_uncaughtExceptionCount(other.m_uncaughtExceptionCount)
			, m_cancelled(other.m_cancelled)
		{
			other.cancel();
		}

		~conditional_scoped_lambda() noexcept(CALL_ON_FAILURE || noexcept(std::declval<FUNC>()()))
		{
			if (!m_cancelled && (is_unwinding_due_to_exception() == CALL_ON_FAILURE))
			{
				m_func();
			}
		}

		void cancel() noexcept
		{
			m_cancelled = true;
		}

	private:

		bool is_unwinding_due_to_exception() const noexcept
		{
			return std::uncaught_exceptions() > m_uncaughtExceptionCount;
		}

		FUNC m_func;
		int m_uncaughtExceptionCount;
		bool m_cancelled;

	};

	/// Returns an object that calls the provided function when it goes out
	/// of scope either normally or due to an uncaught exception unwinding
	/// the stack.
	///
	/// \param func
	/// The function to call when the scope exits.
	/// The function must be noexcept.
	template<typename FUNC>
	auto on_scope_exit(FUNC&& func)
	{
		return scoped_lambda<FUNC>{ std::forward<FUNC>(func) };
	}

	/// Returns an object that calls the provided function when it goes out
	/// of scope due to an uncaught exception unwinding the stack.
	///
	/// \param func
	/// The function to be called if unwinding due to an exception.
	/// The function must be noexcept.
	template<typename FUNC>
	auto on_scope_failure(FUNC&& func)
	{
		return conditional_scoped_lambda<FUNC, true>{ std::forward<FUNC>(func) };
	}

	/// Returns an object that calls the provided function when it goes out
	/// of scope via normal execution (ie. not unwinding due to an exception).
	///
	/// \param func
	/// The function to call if the scope exits normally.
	/// The function does not necessarily need to be noexcept.
	template<typename FUNC>
	auto on_scope_success(FUNC&& func)
	{
		return conditional_scoped_lambda<FUNC, false>{ std::forward<FUNC>(func) };
	}
}

#endif

#include "socket_helpers.hpp"

#if CPPCORO_OS_WINNT
# include <WinSock2.h>
# include <WS2tcpip.h>
# include <MSWSock.h>
# include <Windows.h>

namespace
{
	namespace local
	{
		std::tuple<SOCKET, bool> create_socket(
			int addressFamily,
			int socketType,
			int protocol,
			HANDLE ioCompletionPort)
		{
			// Enumerate available protocol providers for the specified socket type.

			WSAPROTOCOL_INFOW stackInfos[4];
			std::unique_ptr<WSAPROTOCOL_INFOW[]> heapInfos;
			WSAPROTOCOL_INFOW* selectedProtocolInfo = nullptr;

			{
				INT protocols[] = { protocol, 0 };
				DWORD bufferSize = sizeof(stackInfos);
				WSAPROTOCOL_INFOW* infos = stackInfos;

				int protocolCount = ::WSAEnumProtocolsW(protocols, infos, &bufferSize);
				if (protocolCount == SOCKET_ERROR)
				{
					int errorCode = ::WSAGetLastError();
					if (errorCode == WSAENOBUFS)
					{
						DWORD requiredElementCount = bufferSize / sizeof(WSAPROTOCOL_INFOW);
						heapInfos = std::make_unique<WSAPROTOCOL_INFOW[]>(requiredElementCount);
						bufferSize = requiredElementCount * sizeof(WSAPROTOCOL_INFOW);
						infos = heapInfos.get();
						protocolCount = ::WSAEnumProtocolsW(protocols, infos, &bufferSize);
						if (protocolCount == SOCKET_ERROR)
						{
							errorCode = ::WSAGetLastError();
						}
					}

					if (protocolCount == SOCKET_ERROR)
					{
						throw std::system_error(
							errorCode,
							std::system_category(),
							"Error creating socket: WSAEnumProtocolsW");
					}
				}

				if (protocolCount == 0)
				{
					throw std::system_error(
						std::make_error_code(std::errc::protocol_not_supported));
				}

				for (int i = 0; i < protocolCount; ++i)
				{
					auto& info = infos[i];
					if (info.iAddressFamily == addressFamily && info.iProtocol == protocol && info.iSocketType == socketType)
					{
						selectedProtocolInfo = &info;
						break;
					}
				}

				if (selectedProtocolInfo == nullptr)
				{
					throw std::system_error(
						std::make_error_code(std::errc::address_family_not_supported));
				}
			}

			// WSA_FLAG_NO_HANDLE_INHERIT for SDKs earlier than Windows 7.
			constexpr DWORD flagNoInherit = 0x80;

			const DWORD flags = WSA_FLAG_OVERLAPPED | flagNoInherit;

			const SOCKET socketHandle = ::WSASocketW(
				addressFamily, socketType, protocol, selectedProtocolInfo, 0, flags);
			if (socketHandle == INVALID_SOCKET)
			{
				const int errorCode = ::WSAGetLastError();
				throw std::system_error(
					errorCode,
					std::system_category(),
					"Error creating socket: WSASocketW");
			}

			auto closeSocketOnFailure = cppcoro::on_scope_failure([&]
			{
				::closesocket(socketHandle);
			});

			// This is needed on operating systems earlier than Windows 7 to prevent
			// socket handles from being inherited. On Windows 7 or later this is
			// redundant as the WSA_FLAG_NO_HANDLE_INHERIT flag passed to creation
			// above causes the socket to be atomically created with this flag cleared.
			if (!::SetHandleInformation((HANDLE)socketHandle, HANDLE_FLAG_INHERIT, 0))
			{
				const DWORD errorCode = ::GetLastError();
				throw std::system_error(
					errorCode,
					std::system_category(),
					"Error creating socket: SetHandleInformation");
			}

			// Associate the socket with the I/O completion port.
			{
				const HANDLE result = ::CreateIoCompletionPort(
					(HANDLE)socketHandle,
					ioCompletionPort,
					ULONG_PTR(0),
					DWORD(0));
				if (result == nullptr)
				{
					const DWORD errorCode = ::GetLastError();
					throw std::system_error(
						static_cast<int>(errorCode),
						std::system_category(),
						"Error creating socket: CreateIoCompletionPort");
				}
			}

			const bool skipCompletionPortOnSuccess =
				(selectedProtocolInfo->dwServiceFlags1 & XP1_IFS_HANDLES) != 0;

			{
				UCHAR completionModeFlags = FILE_SKIP_SET_EVENT_ON_HANDLE;
				if (skipCompletionPortOnSuccess)
				{
					completionModeFlags |= FILE_SKIP_COMPLETION_PORT_ON_SUCCESS;
				}

				const BOOL ok = ::SetFileCompletionNotificationModes(
					(HANDLE)socketHandle,
					completionModeFlags);
				if (!ok)
				{
					const DWORD errorCode = ::GetLastError();
					throw std::system_error(
						static_cast<int>(errorCode),
						std::system_category(),
						"Error creating socket: SetFileCompletionNotificationModes");
				}
			}

			if (socketType == SOCK_STREAM)
			{
				// Turn off linger so that the destructor doesn't block while closing
				// the socket or silently continue to flush remaining data in the
				// background after ::closesocket() is called, which could fail and
				// we'd never know about it.
				// We expect clients to call Disconnect() or use CloseSend() to cleanly
				// shut-down connections instead.
				BOOL value = TRUE;
				const int result = ::setsockopt(socketHandle,
					SOL_SOCKET,
					SO_DONTLINGER,
					reinterpret_cast<const char*>(&value),
					sizeof(value));
				if (result == SOCKET_ERROR)
				{
					const int errorCode = ::WSAGetLastError();
					throw std::system_error(
						errorCode,
						std::system_category(),
						"Error creating socket: setsockopt(SO_DONTLINGER)");
				}
			}

			return std::make_tuple(socketHandle, skipCompletionPortOnSuccess);
		}
	}
}

cppcoro::net::socket cppcoro::net::socket::create_tcpv4(io_service& ioSvc)
{
	ioSvc.ensure_winsock_initialised();

	auto[socketHandle, skipCompletionPortOnSuccess] = local::create_socket(
		AF_INET, SOCK_STREAM, IPPROTO_TCP, ioSvc.native_iocp_handle());

	socket result(socketHandle, skipCompletionPortOnSuccess);
	result.m_localEndPoint = ipv4_endpoint();
	result.m_remoteEndPoint = ipv4_endpoint();
	return result;
}

cppcoro::net::socket cppcoro::net::socket::create_tcpv6(io_service& ioSvc)
{
	ioSvc.ensure_winsock_initialised();

	auto[socketHandle, skipCompletionPortOnSuccess] = local::create_socket(
		AF_INET6, SOCK_STREAM, IPPROTO_TCP, ioSvc.native_iocp_handle());

	socket result(socketHandle, skipCompletionPortOnSuccess);
	result.m_localEndPoint = ipv6_endpoint();
	result.m_remoteEndPoint = ipv6_endpoint();
	return result;
}

cppcoro::net::socket cppcoro::net::socket::create_udpv4(io_service& ioSvc)
{
	ioSvc.ensure_winsock_initialised();

	auto[socketHandle, skipCompletionPortOnSuccess] = local::create_socket(
		AF_INET, SOCK_DGRAM, IPPROTO_UDP, ioSvc.native_iocp_handle());

	socket result(socketHandle, skipCompletionPortOnSuccess);
	result.m_localEndPoint = ipv4_endpoint();
	result.m_remoteEndPoint = ipv4_endpoint();
	return result;
}

cppcoro::net::socket cppcoro::net::socket::create_udpv6(io_service& ioSvc)
{
	ioSvc.ensure_winsock_initialised();

	auto[socketHandle, skipCompletionPortOnSuccess] = local::create_socket(
		AF_INET6, SOCK_DGRAM, IPPROTO_UDP, ioSvc.native_iocp_handle());

	socket result(socketHandle, skipCompletionPortOnSuccess);
	result.m_localEndPoint = ipv6_endpoint();
	result.m_remoteEndPoint = ipv6_endpoint();
	return result;
}

cppcoro::net::socket::socket(socket&& other) noexcept
	: m_handle(std::exchange(other.m_handle, INVALID_SOCKET))
	, m_skipCompletionOnSuccess(other.m_skipCompletionOnSuccess)
	, m_localEndPoint(std::move(other.m_localEndPoint))
	, m_remoteEndPoint(std::move(other.m_remoteEndPoint))
{}

cppcoro::net::socket::~socket()
{
	if (m_handle != INVALID_SOCKET)
	{
		::closesocket(m_handle);
	}
}

cppcoro::net::socket&
cppcoro::net::socket::operator=(socket&& other) noexcept
{
	auto handle = std::exchange(other.m_handle, INVALID_SOCKET);
	if (m_handle != INVALID_SOCKET)
	{
		::closesocket(m_handle);
	}

	m_handle = handle;
	m_skipCompletionOnSuccess = other.m_skipCompletionOnSuccess;
	m_localEndPoint = other.m_localEndPoint;
	m_remoteEndPoint = other.m_remoteEndPoint;

	return *this;
}

void cppcoro::net::socket::bind(const ip_endpoint& localEndPoint)
{
	SOCKADDR_STORAGE sockaddrStorage = { 0 };
	SOCKADDR* sockaddr = reinterpret_cast<SOCKADDR*>(&sockaddrStorage);
	if (localEndPoint.is_ipv4())
	{
		SOCKADDR_IN& ipv4Sockaddr = *reinterpret_cast<SOCKADDR_IN*>(sockaddr);
		ipv4Sockaddr.sin_family = AF_INET;
		std::memcpy(&ipv4Sockaddr.sin_addr, localEndPoint.to_ipv4().address().bytes(), 4);
		ipv4Sockaddr.sin_port = localEndPoint.to_ipv4().port();
	}
	else
	{
		SOCKADDR_IN6& ipv6Sockaddr = *reinterpret_cast<SOCKADDR_IN6*>(sockaddr);
		ipv6Sockaddr.sin6_family = AF_INET6;
		std::memcpy(&ipv6Sockaddr.sin6_addr, localEndPoint.to_ipv6().address().bytes(), 16);
		ipv6Sockaddr.sin6_port = localEndPoint.to_ipv6().port();
	}

	int result = ::bind(m_handle, sockaddr, sizeof(sockaddrStorage));
	if (result != 0)
	{
		// WSANOTINITIALISED: WSAStartup not called
		// WSAENETDOWN: network subsystem failed
		// WSAEACCES: access denied
		// WSAEADDRINUSE: port in use
		// WSAEADDRNOTAVAIL: address is not an address that can be bound to
		// WSAEFAULT: invalid pointer passed to bind()
		// WSAEINPROGRESS: a callback is in progress
		// WSAEINVAL: socket already bound
		// WSAENOBUFS: system failed to allocate memory
		// WSAENOTSOCK: socket was not a valid socket.
		int errorCode = ::WSAGetLastError();
		throw std::system_error(
			errorCode,
			std::system_category(),
			"Error binding to endpoint: bind()");
	}

	int sockaddrLen = sizeof(sockaddrStorage);
	result = ::getsockname(m_handle, sockaddr, &sockaddrLen);
	if (result == 0)
	{
		m_localEndPoint = cppcoro::net::detail::sockaddr_to_ip_endpoint(*sockaddr);
	}
	else
	{
		m_localEndPoint = localEndPoint;
	}
}

void cppcoro::net::socket::listen()
{
	int result = ::listen(m_handle, SOMAXCONN);
	if (result != 0)
	{
		int errorCode = ::WSAGetLastError();
		throw std::system_error(
			errorCode,
			std::system_category(),
			"Failed to start listening on bound endpoint: listen");
	}
}

void cppcoro::net::socket::listen(std::uint32_t backlog)
{
	if (backlog > 0x7FFFFFFF)
	{
		backlog = 0x7FFFFFFF;
	}

	int result = ::listen(m_handle, (int)backlog);
	if (result != 0)
	{
		// WSANOTINITIALISED: WSAStartup not called
		// WSAENETDOWN: network subsystem failed
		// WSAEADDRINUSE: port in use
		// WSAEINPROGRESS: a callback is in progress
		// WSAEINVAL: socket not yet bound
		// WSAEISCONN: socket already connected
		// WSAEMFILE: no more socket descriptors available
		// WSAENOBUFS: system failed to allocate memory
		// WSAENOTSOCK: socket was not a valid socket.
		// WSAEOPNOTSUPP: The socket does not support listening

		int errorCode = ::WSAGetLastError();
		throw std::system_error(
			errorCode,
			std::system_category(),
			"Failed to start listening on bound endpoint: listen");
	}
}

cppcoro::net::socket_accept_operation
cppcoro::net::socket::accept(socket& acceptingSocket) noexcept
{
	return socket_accept_operation{ *this, acceptingSocket };
}

cppcoro::net::socket_accept_operation_cancellable
cppcoro::net::socket::accept(socket& acceptingSocket, cancellation_token ct) noexcept
{
	return socket_accept_operation_cancellable{ *this, acceptingSocket, std::move(ct) };
}

cppcoro::net::socket_connect_operation
cppcoro::net::socket::connect(const ip_endpoint& remoteEndPoint) noexcept
{
	return socket_connect_operation{ *this, remoteEndPoint };
}

cppcoro::net::socket_connect_operation_cancellable
cppcoro::net::socket::connect(const ip_endpoint& remoteEndPoint, cancellation_token ct) noexcept
{
	return socket_connect_operation_cancellable{ *this, remoteEndPoint, std::move(ct) };
}

cppcoro::net::socket_disconnect_operation
cppcoro::net::socket::disconnect() noexcept
{
	return socket_disconnect_operation(*this);
}

cppcoro::net::socket_disconnect_operation_cancellable
cppcoro::net::socket::disconnect(cancellation_token ct) noexcept
{
	return socket_disconnect_operation_cancellable{ *this, std::move(ct) };
}

cppcoro::net::socket_send_operation
cppcoro::net::socket::send(const void* buffer, std::size_t byteCount) noexcept
{
	return socket_send_operation{ *this, buffer, byteCount };
}

cppcoro::net::socket_send_operation_cancellable
cppcoro::net::socket::send(const void* buffer, std::size_t byteCount, cancellation_token ct) noexcept
{
	return socket_send_operation_cancellable{ *this, buffer, byteCount, std::move(ct) };
}

cppcoro::net::socket_recv_operation
cppcoro::net::socket::recv(void* buffer, std::size_t byteCount) noexcept
{
	return socket_recv_operation{ *this, buffer, byteCount };
}

cppcoro::net::socket_recv_operation_cancellable
cppcoro::net::socket::recv(void* buffer, std::size_t byteCount, cancellation_token ct) noexcept
{
	return socket_recv_operation_cancellable{ *this, buffer, byteCount, std::move(ct) };
}

cppcoro::net::socket_recv_from_operation
cppcoro::net::socket::recv_from(void* buffer, std::size_t byteCount) noexcept
{
	return socket_recv_from_operation{ *this, buffer, byteCount };
}

cppcoro::net::socket_recv_from_operation_cancellable
cppcoro::net::socket::recv_from(void* buffer, std::size_t byteCount, cancellation_token ct) noexcept
{
	return socket_recv_from_operation_cancellable{ *this, buffer, byteCount, std::move(ct) };
}

cppcoro::net::socket_send_to_operation
cppcoro::net::socket::send_to(const ip_endpoint& destination, const void* buffer, std::size_t byteCount) noexcept
{
	return socket_send_to_operation{ *this, destination, buffer, byteCount };
}

cppcoro::net::socket_send_to_operation_cancellable
cppcoro::net::socket::send_to(const ip_endpoint& destination, const void* buffer, std::size_t byteCount, cancellation_token ct) noexcept
{
	return socket_send_to_operation_cancellable{ *this, destination, buffer, byteCount, std::move(ct) };
}

void cppcoro::net::socket::close_send()
{
	int result = ::shutdown(m_handle, SD_SEND);
	if (result == SOCKET_ERROR)
	{
		int errorCode = ::WSAGetLastError();
		throw std::system_error(
			errorCode,
			std::system_category(),
			"failed to close socket send stream: shutdown(SD_SEND)");
	}
}

void cppcoro::net::socket::close_recv()
{
	int result = ::shutdown(m_handle, SD_RECEIVE);
	if (result == SOCKET_ERROR)
	{
		int errorCode = ::WSAGetLastError();
		throw std::system_error(
			errorCode,
			std::system_category(),
			"failed to close socket receive stream: shutdown(SD_RECEIVE)");
	}
}

cppcoro::net::socket::socket(
	cppcoro::detail::win32::socket_t handle,
	bool skipCompletionOnSuccess) noexcept
	: m_handle(handle)
	, m_skipCompletionOnSuccess(skipCompletionOnSuccess)
{
}

#endif
