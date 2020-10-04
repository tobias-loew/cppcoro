///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_LIGHTWEIGHT_MANUAL_RESET_EVENT_HPP_INCLUDED
#define CPPCORO_DETAIL_LIGHTWEIGHT_MANUAL_RESET_EVENT_HPP_INCLUDED

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

#if CPPCORO_OS_LINUX || (CPPCORO_OS_WINNT >= 0x0602)
# include <atomic>
# include <cstdint>
#elif CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
#else
# include <mutex>
# include <condition_variable>
#endif

namespace cppcoro
{
	namespace detail
	{
		class lightweight_manual_reset_event
		{
		public:

			lightweight_manual_reset_event(bool initiallySet = false);

			~lightweight_manual_reset_event();

			void set() noexcept;

			void reset() noexcept;

			void wait() noexcept;

		private:

#if CPPCORO_OS_LINUX
			std::atomic<int> m_value;
#elif CPPCORO_OS_WINNT >= 0x0602
			// Windows 8 or newer we can use WaitOnAddress()
			std::atomic<std::uint8_t> m_value;
#elif CPPCORO_OS_WINNT
			// Before Windows 8 we need to use a WIN32 manual reset event.
			cppcoro::detail::win32::handle_t m_eventHandle;
#else
			// For other platforms that don't have a native futex
			// or manual reset event we can just use a std::mutex
			// and std::condition_variable to perform the wait.
			// Not so lightweight, but should be portable to all platforms.
			std::mutex m_mutex;
			std::condition_variable m_cv;
			bool m_isSet;
#endif
		};
	}
}

#endif

#include <system_error>

#if CPPCORO_OS_WINNT
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <Windows.h>

# if CPPCORO_OS_WINNT >= 0x0602

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_value(initiallySet ? 1 : 0)
{}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	m_value.store(1, std::memory_order_release);
	::WakeByAddressAll(&m_value);
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	m_value.store(0, std::memory_order_relaxed);
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	// Wait in a loop as WaitOnAddress() can have spurious wake-ups.
	int value = m_value.load(std::memory_order_acquire);
	BOOL ok = TRUE;
	while (value == 0)
	{
		if (!ok)
		{
			// Previous call to WaitOnAddress() failed for some reason.
			// Put thread to sleep to avoid sitting in a busy loop if it keeps failing.
			::Sleep(1);
		}

		ok = ::WaitOnAddress(&m_value, &value, sizeof(m_value), INFINITE);
		value = m_value.load(std::memory_order_acquire);
	}
}

# else

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_eventHandle(::CreateEventW(nullptr, TRUE, initiallySet, nullptr))
{
	if (m_eventHandle == NULL)
	{
		const DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category()
		};
	}
}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
	// Ignore failure to close the object.
	// We can't do much here as we want destructor to be noexcept.
	(void)::CloseHandle(m_eventHandle);
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	if (!::SetEvent(m_eventHandle))
	{
		std::abort();
	}
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	if (!::ResetEvent(m_eventHandle))
	{
		std::abort();
	}
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	constexpr BOOL alertable = FALSE;
	DWORD waitResult = ::WaitForSingleObjectEx(m_eventHandle, INFINITE, alertable);
	if (waitResult == WAIT_FAILED)
	{
		std::abort();
	}
}

# endif

#elif CPPCORO_OS_LINUX

#include <unistd.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <linux/futex.h>
#include <cerrno>
#include <climits>
#include <cassert>

namespace
{
	namespace local
	{
		// No futex() function provided by libc.
		// Wrap the syscall ourselves here.
		int futex(
			int* UserAddress,
			int FutexOperation,
			int Value,
			const struct timespec* timeout,
			int* UserAddress2,
			int Value3)
		{
			return syscall(
				SYS_futex,
				UserAddress,
				FutexOperation,
				Value,
				timeout,
				UserAddress2,
				Value3);
		}
	}
}

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_value(initiallySet ? 1 : 0)
{}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	m_value.store(1, std::memory_order_release);

	constexpr int numberOfWaitersToWakeUp = INT_MAX;

	[[maybe_unused]] int numberOfWaitersWokenUp = local::futex(
		reinterpret_cast<int*>(&m_value),
		FUTEX_WAKE_PRIVATE,
		numberOfWaitersToWakeUp,
		nullptr,
		nullptr,
		0);

	// There are no errors expected here unless this class (or the caller)
	// has done something wrong.
	assert(numberOfWaitersWokenUp != -1);
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	m_value.store(0, std::memory_order_relaxed);
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	// Wait in a loop as futex() can have spurious wake-ups.
	int oldValue = m_value.load(std::memory_order_acquire);
	while (oldValue == 0)
	{
		int result = local::futex(
			reinterpret_cast<int*>(&m_value),
			FUTEX_WAIT_PRIVATE,
			oldValue,
			nullptr,
			nullptr,
			0);
		if (result == -1)
		{
			if (errno == EAGAIN)
			{
				// The state was changed from zero before we could wait.
				// Must have been changed to 1.
				return;
			}

			// Other errors we'll treat as transient and just read the
			// value and go around the loop again.
		}

		oldValue = m_value.load(std::memory_order_acquire);
	}
}

#else

cppcoro::detail::lightweight_manual_reset_event::lightweight_manual_reset_event(bool initiallySet)
	: m_isSet(initiallySet)
{
}

cppcoro::detail::lightweight_manual_reset_event::~lightweight_manual_reset_event()
{
}

void cppcoro::detail::lightweight_manual_reset_event::set() noexcept
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_isSet = true;
	m_cv.notify_all();
}

void cppcoro::detail::lightweight_manual_reset_event::reset() noexcept
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_isSet = false;
}

void cppcoro::detail::lightweight_manual_reset_event::wait() noexcept
{
	std::unique_lock<std::mutex> lock(m_mutex);
	m_cv.wait(lock, [this] { return m_isSet; });
}

#endif
