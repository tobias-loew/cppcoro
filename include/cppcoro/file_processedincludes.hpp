///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_FILE_HPP_INCLUDED
#define CPPCORO_FILE_HPP_INCLUDED

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
#ifndef CPPCORO_FILE_OPEN_MODE_HPP_INCLUDED
#define CPPCORO_FILE_OPEN_MODE_HPP_INCLUDED

namespace cppcoro
{
	enum class file_open_mode
	{
		/// Open an existing file.
		///
		/// If file does not already exist when opening the file then raises
		/// an exception.
		open_existing,

		/// Create a new file, overwriting an existing file if one exists.
		///
		/// If a file exists at the path then it is overwitten with a new file.
		/// If no file exists at the path then a new one is created.
		create_always,

		/// Create a new file.
		///
		/// If the file already exists then raises an exception.
		create_new,

		/// Open the existing file if one exists, otherwise create a new empty
		/// file.
		create_or_open,

		/// Open the existing file, truncating the file size to zero.
		///
		/// If the file does not exist then raises an exception.
		truncate_existing
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_FILE_SHARE_MODE_HPP_INCLUDED
#define CPPCORO_FILE_SHARE_MODE_HPP_INCLUDED

namespace cppcoro
{
	enum class file_share_mode
	{
		/// Don't allow any other processes to open the file concurrently.
		none = 0,

		/// Allow other processes to open the file in read-only mode
		/// concurrently with this process opening the file.
		read = 1,

		/// Allow other processes to open the file in write-only mode
		/// concurrently with this process opening the file.
		write = 2,

		/// Allow other processes to open the file in read and/or write mode
		/// concurrently with this process opening the file.
		read_write = read | write,

		/// Allow other processes to delete the file while this process
		/// has the file open.
		delete_ = 4
	};

	constexpr file_share_mode operator|(file_share_mode a, file_share_mode b)
	{
		return static_cast<file_share_mode>(
			static_cast<int>(a) | static_cast<int>(b));
	}

	constexpr file_share_mode operator&(file_share_mode a, file_share_mode b)
	{
		return static_cast<file_share_mode>(
			static_cast<int>(a) & static_cast<int>(b));
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_FILE_BUFFERING_MODE_HPP_INCLUDED
#define CPPCORO_FILE_BUFFERING_MODE_HPP_INCLUDED

namespace cppcoro
{
	enum class file_buffering_mode
	{
		default_ = 0,
		sequential = 1,
		random_access = 2,
		unbuffered = 4,
		write_through = 8,
		temporary = 16
	};

	constexpr file_buffering_mode operator&(file_buffering_mode a, file_buffering_mode b)
	{
		return static_cast<file_buffering_mode>(
			static_cast<int>(a) & static_cast<int>(b));
	}

	constexpr file_buffering_mode operator|(file_buffering_mode a, file_buffering_mode b)
	{
		return static_cast<file_buffering_mode>(static_cast<int>(a) | static_cast<int>(b));
	}
}

#endif

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
#endif

#include <experimental/filesystem>

namespace cppcoro
{
	class io_service;

	class file
	{
	public:

		file(file&& other) noexcept = default;

		virtual ~file();

		/// Get the size of the file in bytes.
		std::uint64_t size() const;

	protected:

#if CPPCORO_OS_WINNT
		file(detail::win32::safe_handle&& fileHandle) noexcept;

		static detail::win32::safe_handle open(
			detail::win32::dword_t fileAccess,
			io_service& ioService,
			const std::filesystem::path& path,
			file_open_mode openMode,
			file_share_mode shareMode,
			file_buffering_mode bufferingMode);

		detail::win32::safe_handle m_fileHandle;
#endif

	};
}

#endif
