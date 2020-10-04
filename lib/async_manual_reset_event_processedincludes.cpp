///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_ASYNC_MANUAL_RESET_EVENT_HPP_INCLUDED
#define CPPCORO_ASYNC_MANUAL_RESET_EVENT_HPP_INCLUDED

#include <coroutine>
#include <atomic>
#include <cstdint>

namespace cppcoro
{
	class async_manual_reset_event_operation;

	/// An async manual-reset event is a coroutine synchronisation abstraction
	/// that allows one or more coroutines to wait until some thread calls
	/// set() on the event.
	///
	/// When a coroutine awaits a 'set' event the coroutine continues without
	/// suspending. Otherwise, if it awaits a 'not set' event the coroutine is
	/// suspended and is later resumed inside the call to 'set()'.
	///
	/// \seealso async_auto_reset_event
	class async_manual_reset_event
	{
	public:

		/// Initialise the event to either 'set' or 'not set' state.
		///
		/// \param initiallySet
		/// If 'true' then initialises the event to the 'set' state, otherwise
		/// initialises the event to the 'not set' state.
		async_manual_reset_event(bool initiallySet = false) noexcept;

		~async_manual_reset_event();

		/// Wait for the event to enter the 'set' state.
		///
		/// If the event is already 'set' then the coroutine continues without
		/// suspending.
		///
		/// Otherwise, the coroutine is suspended and later resumed when some
		/// thread calls 'set()'. The coroutine will be resumed inside the next
		/// call to 'set()'.
		async_manual_reset_event_operation operator co_await() const noexcept;

		/// Query if the event is currently in the 'set' state.
		bool is_set() const noexcept;

		/// Set the state of the event to 'set'.
		///
		/// If there are pending coroutines awaiting the event then all
		/// pending coroutines are resumed within this call.
		/// Any coroutines that subsequently await the event will continue
		/// without suspending.
		///
		/// This operation is a no-op if the event was already 'set'.
		void set() noexcept;

		/// Set the state of the event to 'not-set'.
		///
		/// Any coroutines that subsequently await the event will suspend
		/// until some thread calls 'set()'.
		///
		/// This is a no-op if the state was already 'not set'.
		void reset() noexcept;

	private:

		friend class async_manual_reset_event_operation;

		// This variable has 3 states:
		// - this    - The state is 'set'.
		// - nullptr - The state is 'not set' with no waiters.
		// - other   - The state is 'not set'.
		//             Points to an 'async_manual_reset_event_operation' that is
		//             the head of a linked-list of waiters.
		mutable std::atomic<void*> m_state;

	};

	class async_manual_reset_event_operation
	{
	public:

		explicit async_manual_reset_event_operation(const async_manual_reset_event& event) noexcept;

		bool await_ready() const noexcept;
		bool await_suspend(std::coroutine_handle<> awaiter) noexcept;
		void await_resume() const noexcept {}

	private:

		friend class async_manual_reset_event;

		const async_manual_reset_event& m_event;
		async_manual_reset_event_operation* m_next;
		std::coroutine_handle<> m_awaiter;

	};
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

cppcoro::async_manual_reset_event::async_manual_reset_event(bool initiallySet) noexcept
	: m_state(initiallySet ? static_cast<void*>(this) : nullptr)
{}

cppcoro::async_manual_reset_event::~async_manual_reset_event()
{
	// There should be no coroutines still awaiting the event.
	assert(
		m_state.load(std::memory_order_relaxed) == nullptr ||
		m_state.load(std::memory_order_relaxed) == static_cast<void*>(this));
}

bool cppcoro::async_manual_reset_event::is_set() const noexcept
{
	return m_state.load(std::memory_order_acquire) == static_cast<const void*>(this);
}

cppcoro::async_manual_reset_event_operation
cppcoro::async_manual_reset_event::operator co_await() const noexcept
{
	return async_manual_reset_event_operation{ *this };
}

void cppcoro::async_manual_reset_event::set() noexcept
{
	void* const setState = static_cast<void*>(this);

	// Needs 'release' semantics so that prior writes are visible to event awaiters
	// that synchronise either via 'is_set()' or 'operator co_await()'.
	// Needs 'acquire' semantics in case there are any waiters so that we see
	// prior writes to the waiting coroutine's state and to the contents of
	// the queued async_manual_reset_event_operation objects.
	void* oldState = m_state.exchange(setState, std::memory_order_acq_rel);
	if (oldState != setState)
	{
		auto* current = static_cast<async_manual_reset_event_operation*>(oldState);
		while (current != nullptr)
		{
			auto* next = current->m_next;
			current->m_awaiter.resume();
			current = next;
		}
	}
}

void cppcoro::async_manual_reset_event::reset() noexcept
{
	void* oldState = static_cast<void*>(this);
	m_state.compare_exchange_strong(oldState, nullptr, std::memory_order_relaxed);
}

cppcoro::async_manual_reset_event_operation::async_manual_reset_event_operation(
	const async_manual_reset_event& event) noexcept
	: m_event(event)
{
}

bool cppcoro::async_manual_reset_event_operation::await_ready() const noexcept
{
	return m_event.is_set();
}

bool cppcoro::async_manual_reset_event_operation::await_suspend(
	std::coroutine_handle<> awaiter) noexcept
{
	m_awaiter = awaiter;

	const void* const setState = static_cast<const void*>(&m_event);

	void* oldState = m_event.m_state.load(std::memory_order_acquire);
	do
	{
		if (oldState == setState)
		{
			// State is now 'set' no need to suspend.
			return false;
		}

		m_next = static_cast<async_manual_reset_event_operation*>(oldState);
	} while (!m_event.m_state.compare_exchange_weak(
		oldState,
		static_cast<void*>(this),
		std::memory_order_release,
		std::memory_order_acquire));

	// Successfully queued this waiter to the list.
	return true;
}
