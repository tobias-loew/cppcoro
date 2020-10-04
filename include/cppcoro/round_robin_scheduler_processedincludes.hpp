///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_ROUND_ROBIN_SCHEDULER_HPP_INCLUDED
#define CPPCORO_ROUND_ROBIN_SCHEDULER_HPP_INCLUDED

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

#include <coroutine>
#include <array>
#include <cassert>
#include <algorithm>
#include <utility>

namespace cppcoro
{
#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
	/// This is a scheduler class that schedules coroutines in a round-robin
	/// fashion once N coroutines have been scheduled to it.
	///
	/// Only supports access from a single thread at a time so
	///
	/// This implementation was inspired by Gor Nishanov's CppCon 2018 talk
	/// about nano-coroutines.
	///
	/// The implementation relies on symmetric transfer and noop_coroutine()
	/// and so only works with a relatively recent version of Clang and does
	/// not yet work with MSVC.
	template<size_t N>
	class round_robin_scheduler
	{
		static_assert(
			N >= 2,
			"Round robin scheduler must be configured to support at least two coroutines");

		class schedule_operation
		{
		public:
			explicit schedule_operation(round_robin_scheduler& s) noexcept : m_scheduler(s) {}

			bool await_ready() noexcept
			{
				return false;
			}

			std::coroutine_handle<> await_suspend(
				std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				return m_scheduler.exchange_next(awaitingCoroutine);
			}

			void await_resume() noexcept {}

		private:
			round_robin_scheduler& m_scheduler;
		};

		friend class schedule_operation;

	public:
		round_robin_scheduler() noexcept
			: m_index(0)
			, m_noop(std::noop_coroutine())
		{
			for (size_t i = 0; i < N - 1; ++i)
			{
				m_coroutines[i] = m_noop();
			}
		}

		~round_robin_scheduler()
		{
			// All tasks should have been joined before calling destructor.
			assert(std::all_of(
				m_coroutines.begin(),
				m_coroutines.end(),
				[&](auto h) { return h == m_noop; }));
		}

		schedule_operation schedule() noexcept
		{
			return schedule_operation{ *this };
		}

		/// Resume any queued coroutines until there are no more coroutines.
		void drain() noexcept
		{
			size_t countRemaining = N - 1;
			do
			{
				auto nextToResume = exchange_next(m_noop);
				if (nextToResume != m_noop)
				{
					nextToResume.resume();
					countRemaining = N - 1;
				}
				else
				{
					--countRemaining;
				}
			} while (countRemaining > 0);
		}

	private:

		std::coroutine_handle exchange_next(
			std::coroutine_handle<> coroutine) noexcept
		{
			auto coroutineToResume = std::exchange(
				m_scheduler.m_coroutines[m_scheduler.m_index],
				awaitingCoroutine);
			m_scheduler.m_index = m_scheduler.m_index < (N - 2) ? m_scheduler.m_index + 1 : 0;
			return coroutineToResume;
		}

		size_t m_index;
		const std::coroutine_handle<> m_noop;
		std::array<std::coroutine_handle<>, N - 1> m_coroutines;
	};
#endif
}

#endif
