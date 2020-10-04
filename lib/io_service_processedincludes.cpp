///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

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

#include <system_error>
#include <cassert>
#include <algorithm>
#include <thread>

#if CPPCORO_OS_WINNT
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# ifndef NOMINMAX
#  define NOMINMAX
# endif
# include <WinSock2.h>
# include <WS2tcpip.h>
# include <MSWSock.h>
# include <Windows.h>
#endif

namespace
{
#if CPPCORO_OS_WINNT
	cppcoro::detail::win32::safe_handle create_io_completion_port(std::uint32_t concurrencyHint)
	{
		HANDLE handle = ::CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, concurrencyHint);
		if (handle == NULL)
		{
			DWORD errorCode = ::GetLastError();
			throw std::system_error
			{
				static_cast<int>(errorCode),
				std::system_category(),
				"Error creating io_service: CreateIoCompletionPort"
			};
		}

		return cppcoro::detail::win32::safe_handle{ handle };
	}

	cppcoro::detail::win32::safe_handle create_auto_reset_event()
	{
		HANDLE eventHandle = ::CreateEventW(nullptr, FALSE, FALSE, nullptr);
		if (eventHandle == NULL)
		{
			const DWORD errorCode = ::GetLastError();
			throw std::system_error
			{
				static_cast<int>(errorCode),
				std::system_category(),
				"Error creating manual reset event: CreateEventW"
			};
		}

		return cppcoro::detail::win32::safe_handle{ eventHandle };
	}

	cppcoro::detail::win32::safe_handle create_waitable_timer_event()
	{
		const BOOL isManualReset = FALSE;
		HANDLE handle = ::CreateWaitableTimerW(nullptr, isManualReset, nullptr);
		if (handle == nullptr)
		{
			const DWORD errorCode = ::GetLastError();
			throw std::system_error
			{
				static_cast<int>(errorCode),
				std::system_category()
			};
		}

		return cppcoro::detail::win32::safe_handle{ handle };
	}
#endif
}

/// \brief
/// A queue of pending timers that supports efficiently determining
/// and dequeueing the earliest-due timers in the queue.
///
/// Implementation utilises a heap-sorted vector of entries with an
/// additional sorted linked-list that can be used as a fallback in
/// cases that there was insufficient memory to store all timer
/// entries in the vector.
///
/// This fallback is required to guarantee that all operations on this
/// queue are noexcept.s
class cppcoro::io_service::timer_queue
{
public:

	using time_point = std::chrono::high_resolution_clock::time_point;

	timer_queue() noexcept;

	~timer_queue();

	bool is_empty() const noexcept;

	time_point earliest_due_time() const noexcept;

	void enqueue_timer(cppcoro::io_service::timed_schedule_operation* timer) noexcept;

	void dequeue_due_timers(
		time_point currentTime,
		cppcoro::io_service::timed_schedule_operation*& timerList) noexcept;

	void remove_cancelled_timers(
		cppcoro::io_service::timed_schedule_operation*& timerList) noexcept;

private:

	struct timer_entry
	{
		timer_entry(cppcoro::io_service::timed_schedule_operation* timer)
			: m_dueTime(timer->m_resumeTime)
			, m_timer(timer)
		{}

		time_point m_dueTime;
		cppcoro::io_service::timed_schedule_operation* m_timer;
	};

	static bool compare_entries(const timer_entry& a, const timer_entry& b) noexcept
	{
		return a.m_dueTime > b.m_dueTime;
	}

	// A heap-sorted list of active timer entries
	// Earliest due timer is at the front of the queue
	std::vector<timer_entry> m_timerEntries;

	// Linked-list of overflow timer entries used in case there was
	// insufficient memory available to grow m_timerEntries.
	// List is sorted in ascending order of due-time using insertion-sort.
	// This is required to support the noexcept guarantee of enqueue_timer().
	cppcoro::io_service::timed_schedule_operation* m_overflowTimers;

};

cppcoro::io_service::timer_queue::timer_queue() noexcept
	: m_timerEntries()
	, m_overflowTimers(nullptr)
{}

cppcoro::io_service::timer_queue::~timer_queue()
{
	assert(is_empty());
}

bool cppcoro::io_service::timer_queue::is_empty() const noexcept
{
	return m_timerEntries.empty() && m_overflowTimers == nullptr;
}

cppcoro::io_service::timer_queue::time_point
cppcoro::io_service::timer_queue::earliest_due_time() const noexcept
{
	if (!m_timerEntries.empty())
	{
		if (m_overflowTimers != nullptr)
		{
			return std::min(
				m_timerEntries.front().m_dueTime,
				m_overflowTimers->m_resumeTime);
		}

		return m_timerEntries.front().m_dueTime;
	}
	else if (m_overflowTimers != nullptr)
	{
		return m_overflowTimers->m_resumeTime;
	}

	return time_point::max();
}

void cppcoro::io_service::timer_queue::enqueue_timer(
	cppcoro::io_service::timed_schedule_operation* timer) noexcept
{
	try
	{
		m_timerEntries.emplace_back(timer);
		std::push_heap(m_timerEntries.begin(), m_timerEntries.end(), compare_entries);
	}
	catch (...)
	{
		const auto& newDueTime = timer->m_resumeTime;

		auto** current = &m_overflowTimers;
		while ((*current) != nullptr && (*current)->m_resumeTime <= newDueTime)
		{
			current = &(*current)->m_next;
		}

		timer->m_next = *current;
		*current = timer;
	}
}

void cppcoro::io_service::timer_queue::dequeue_due_timers(
	time_point currentTime,
	cppcoro::io_service::timed_schedule_operation*& timerList) noexcept
{
	while (!m_timerEntries.empty() && m_timerEntries.front().m_dueTime <= currentTime)
	{
		auto* timer = m_timerEntries.front().m_timer;
		std::pop_heap(m_timerEntries.begin(), m_timerEntries.end(), compare_entries);
		m_timerEntries.pop_back();

		timer->m_next = timerList;
		timerList = timer;
	}

	while (m_overflowTimers != nullptr && m_overflowTimers->m_resumeTime <= currentTime)
	{
		auto* timer = m_overflowTimers;
		m_overflowTimers = timer->m_next;
		timer->m_next = timerList;
		timerList = timer;
	}
}

void cppcoro::io_service::timer_queue::remove_cancelled_timers(
	cppcoro::io_service::timed_schedule_operation*& timerList) noexcept
{
	// Perform a linear scan of all timers looking for any that have
	// had cancellation requested.

	const auto addTimerToList = [&](timed_schedule_operation* timer)
	{
		timer->m_next = timerList;
		timerList = timer;
	};

	const auto isTimerCancelled = [](const timer_entry& entry)
	{
		return entry.m_timer->m_cancellationToken.is_cancellation_requested();
	};

	auto firstCancelledEntry = std::find_if(
		m_timerEntries.begin(),
		m_timerEntries.end(),
		isTimerCancelled);
	if (firstCancelledEntry != m_timerEntries.end())
	{
		auto nonCancelledEnd = firstCancelledEntry;
		addTimerToList(nonCancelledEnd->m_timer);

		for (auto iter = firstCancelledEntry + 1;
			iter != m_timerEntries.end();
			++iter)
		{
			if (isTimerCancelled(*iter))
			{
				addTimerToList(iter->m_timer);
			}
			else
			{
				*nonCancelledEnd++ = std::move(*iter);
			}
		}

		m_timerEntries.erase(nonCancelledEnd, m_timerEntries.end());

		std::make_heap(
			m_timerEntries.begin(),
			m_timerEntries.end(),
			compare_entries);
	}

	{
		timed_schedule_operation** current = &m_overflowTimers;
		while ((*current) != nullptr)
		{
			auto* timer = (*current);
			if (timer->m_cancellationToken.is_cancellation_requested())
			{
				*current = timer->m_next;
				addTimerToList(timer);
			}
			else
			{
				current = &timer->m_next;
			}
		}
	}
}

class cppcoro::io_service::timer_thread_state
{
public:

	timer_thread_state();
	~timer_thread_state();

	timer_thread_state(const timer_thread_state& other) = delete;
	timer_thread_state& operator=(const timer_thread_state& other) = delete;

	void request_timer_cancellation() noexcept;

	void run() noexcept;

	void wake_up_timer_thread() noexcept;

#if CPPCORO_OS_WINNT
	detail::win32::safe_handle m_wakeUpEvent;
	detail::win32::safe_handle m_waitableTimerEvent;
#endif

	std::atomic<io_service::timed_schedule_operation*> m_newlyQueuedTimers;
	std::atomic<bool> m_timerCancellationRequested;
	std::atomic<bool> m_shutDownRequested;

	std::thread m_thread;
};



cppcoro::io_service::io_service()
	: io_service(0)
{
}

cppcoro::io_service::io_service(std::uint32_t concurrencyHint)
	: m_threadState(0)
	, m_workCount(0)
#if CPPCORO_OS_WINNT
	, m_iocpHandle(create_io_completion_port(concurrencyHint))
	, m_winsockInitialised(false)
	, m_winsockInitialisationMutex()
#endif
	, m_scheduleOperations(nullptr)
	, m_timerState(nullptr)
{
}

cppcoro::io_service::~io_service()
{
	assert(m_scheduleOperations.load(std::memory_order_relaxed) == nullptr);
	assert(m_threadState.load(std::memory_order_relaxed) < active_thread_count_increment);

	delete m_timerState.load(std::memory_order_relaxed);

#if CPPCORO_OS_WINNT
	if (m_winsockInitialised.load(std::memory_order_relaxed))
	{
		// TODO: Should we be checking return-code here?
		// Don't want to throw from the destructor, so perhaps just log an error?
		(void)::WSACleanup();
	}
#endif
}

cppcoro::io_service::schedule_operation cppcoro::io_service::schedule() noexcept
{
	return schedule_operation{ *this };
}

std::uint64_t cppcoro::io_service::process_events()
{
	std::uint64_t eventCount = 0;
	if (try_enter_event_loop())
	{
		auto exitLoop = on_scope_exit([&] { exit_event_loop(); });

		constexpr bool waitForEvent = true;
		while (try_process_one_event(waitForEvent))
		{
			++eventCount;
		}
	}

	return eventCount;
}

std::uint64_t cppcoro::io_service::process_pending_events()
{
	std::uint64_t eventCount = 0;
	if (try_enter_event_loop())
	{
		auto exitLoop = on_scope_exit([&] { exit_event_loop(); });

		constexpr bool waitForEvent = false;
		while (try_process_one_event(waitForEvent))
		{
			++eventCount;
		}
	}

	return eventCount;
}

std::uint64_t cppcoro::io_service::process_one_event()
{
	std::uint64_t eventCount = 0;
	if (try_enter_event_loop())
	{
		auto exitLoop = on_scope_exit([&] { exit_event_loop(); });

		constexpr bool waitForEvent = true;
		if (try_process_one_event(waitForEvent))
		{
			++eventCount;
		}
	}

	return eventCount;
}

std::uint64_t cppcoro::io_service::process_one_pending_event()
{
	std::uint64_t eventCount = 0;
	if (try_enter_event_loop())
	{
		auto exitLoop = on_scope_exit([&] { exit_event_loop(); });

		constexpr bool waitForEvent = false;
		if (try_process_one_event(waitForEvent))
		{
			++eventCount;
		}
	}

	return eventCount;
}

void cppcoro::io_service::stop() noexcept
{
	const auto oldState = m_threadState.fetch_or(stop_requested_flag, std::memory_order_release);
	if ((oldState & stop_requested_flag) == 0)
	{
		for (auto activeThreadCount = oldState / active_thread_count_increment;
			activeThreadCount > 0;
			--activeThreadCount)
		{
			post_wake_up_event();
		}
	}
}

void cppcoro::io_service::reset()
{
	const auto oldState = m_threadState.fetch_and(~stop_requested_flag, std::memory_order_relaxed);

	// Check that there were no active threads running the event loop.
	assert(oldState == stop_requested_flag);
}

bool cppcoro::io_service::is_stop_requested() const noexcept
{
	return (m_threadState.load(std::memory_order_acquire) & stop_requested_flag) != 0;
}

void cppcoro::io_service::notify_work_started() noexcept
{
	m_workCount.fetch_add(1, std::memory_order_relaxed);
}

void cppcoro::io_service::notify_work_finished() noexcept
{
	if (m_workCount.fetch_sub(1, std::memory_order_relaxed) == 1)
	{
		stop();
	}
}

cppcoro::detail::win32::handle_t cppcoro::io_service::native_iocp_handle() noexcept
{
	return m_iocpHandle.handle();
}

#if CPPCORO_OS_WINNT

void cppcoro::io_service::ensure_winsock_initialised()
{
	if (!m_winsockInitialised.load(std::memory_order_acquire))
	{
		std::lock_guard<std::mutex> lock(m_winsockInitialisationMutex);
		if (!m_winsockInitialised.load(std::memory_order_acquire))
		{
			const WORD requestedVersion = MAKEWORD(2, 2);
			WSADATA winsockData;
			const int result = ::WSAStartup(requestedVersion, &winsockData);
			if (result == SOCKET_ERROR)
			{
				const int errorCode = ::WSAGetLastError();
				throw std::system_error(
					errorCode,
					std::system_category(),
					"Error initialsing winsock: WSAStartup");
			}

			m_winsockInitialised.store(true, std::memory_order_release);
		}
	}
}

#endif // CPPCORO_OS_WINNT

void cppcoro::io_service::schedule_impl(schedule_operation* operation) noexcept
{
#if CPPCORO_OS_WINNT
	const BOOL ok = ::PostQueuedCompletionStatus(
		m_iocpHandle.handle(),
		0,
		reinterpret_cast<ULONG_PTR>(operation->m_awaiter.address()),
		nullptr);
	if (!ok)
	{
		// Failed to post to the I/O completion port.
		//
		// This is most-likely because the queue is currently full.
		//
		// We'll queue up the operation to a linked-list using a lock-free
		// push and defer the dispatch to the completion port until some I/O
		// thread next enters its event loop.
		auto* head = m_scheduleOperations.load(std::memory_order_acquire);
		do
		{
			operation->m_next = head;
		} while (!m_scheduleOperations.compare_exchange_weak(
			head,
			operation,
			std::memory_order_release,
			std::memory_order_acquire));
	}
#endif
}

void cppcoro::io_service::try_reschedule_overflow_operations() noexcept
{
#if CPPCORO_OS_WINNT
	auto* operation = m_scheduleOperations.exchange(nullptr, std::memory_order_acquire);
	while (operation != nullptr)
	{
		auto* next = operation->m_next;
		BOOL ok = ::PostQueuedCompletionStatus(
			m_iocpHandle.handle(),
			0,
			reinterpret_cast<ULONG_PTR>(operation->m_awaiter.address()),
			nullptr);
		if (!ok)
		{
			// Still unable to queue these operations.
			// Put them back on the list of overflow operations.
			auto* tail = operation;
			while (tail->m_next != nullptr)
			{
				tail = tail->m_next;
			}

			schedule_operation* head = nullptr;
			while (!m_scheduleOperations.compare_exchange_weak(
				head,
				operation,
				std::memory_order_release,
				std::memory_order_relaxed))
			{
				tail->m_next = head;
			}

			return;
		}

		operation = next;
	}
#endif
}

bool cppcoro::io_service::try_enter_event_loop() noexcept
{
	auto currentState = m_threadState.load(std::memory_order_relaxed);
	do
	{
		if ((currentState & stop_requested_flag) != 0)
		{
			return false;
		}
	} while (!m_threadState.compare_exchange_weak(
		currentState,
		currentState + active_thread_count_increment,
		std::memory_order_relaxed));

	return true;
}

void cppcoro::io_service::exit_event_loop() noexcept
{
	m_threadState.fetch_sub(active_thread_count_increment, std::memory_order_relaxed);
}

bool cppcoro::io_service::try_process_one_event(bool waitForEvent)
{
#if CPPCORO_OS_WINNT
	if (is_stop_requested())
	{
		return false;
	}

	const DWORD timeout = waitForEvent ? INFINITE : 0;

	while (true)
	{
		// Check for any schedule_operation objects that were unable to be
		// queued to the I/O completion port and try to requeue them now.
		try_reschedule_overflow_operations();

		DWORD numberOfBytesTransferred = 0;
		ULONG_PTR completionKey = 0;
		LPOVERLAPPED overlapped = nullptr;
		BOOL ok = ::GetQueuedCompletionStatus(
			m_iocpHandle.handle(),
			&numberOfBytesTransferred,
			&completionKey,
			&overlapped,
			timeout);
		if (overlapped != nullptr)
		{
			DWORD errorCode = ok ? ERROR_SUCCESS : ::GetLastError();

			auto* state = static_cast<detail::win32::io_state*>(
				reinterpret_cast<detail::win32::overlapped*>(overlapped));

			state->m_callback(
				state,
				errorCode,
				numberOfBytesTransferred,
				completionKey);

			return true;
		}
		else if (ok)
		{
			if (completionKey != 0)
			{
				// This was a coroutine scheduled via a call to
				// io_service::schedule().
				std::coroutine_handle<>::from_address(
					reinterpret_cast<void*>(completionKey)).resume();
				return true;
			}

			// Empty event is a wake-up request, typically associated with a
			// request to exit the event loop.
			// However, there may be spurious such events remaining in the queue
			// from a previous call to stop() that has since been reset() so we
			// need to check whether stop is still required.
			if (is_stop_requested())
			{
				return false;
			}
		}
		else
		{
			const DWORD errorCode = ::GetLastError();
			if (errorCode == WAIT_TIMEOUT)
			{
				return false;
			}

			throw std::system_error
			{
				static_cast<int>(errorCode),
				std::system_category(),
				"Error retrieving item from io_service queue: GetQueuedCompletionStatus"
			};
		}
	}
#endif
}

void cppcoro::io_service::post_wake_up_event() noexcept
{
#if CPPCORO_OS_WINNT
	// We intentionally ignore the return code here.
	//
	// Assume that if posting an event failed that it failed because the queue was full
	// and the system is out of memory. In this case threads should find other events
	// in the queue next time they check anyway and thus wake-up.
	(void)::PostQueuedCompletionStatus(m_iocpHandle.handle(), 0, 0, nullptr);
#endif
}

cppcoro::io_service::timer_thread_state*
cppcoro::io_service::ensure_timer_thread_started()
{
	auto* timerState = m_timerState.load(std::memory_order_acquire);
	if (timerState == nullptr)
	{
		auto newTimerState = std::make_unique<timer_thread_state>();
		if (m_timerState.compare_exchange_strong(
			timerState,
			newTimerState.get(),
			std::memory_order_release,
			std::memory_order_acquire))
		{
			// We managed to install our timer_thread_state before some
			// other thread did, don't free it here - it will be freed in
			// the io_service destructor.
			timerState = newTimerState.release();
		}
	}

	return timerState;
}

cppcoro::io_service::timer_thread_state::timer_thread_state()
#if CPPCORO_OS_WINNT
	: m_wakeUpEvent(create_auto_reset_event())
	, m_waitableTimerEvent(create_waitable_timer_event())
#endif
	, m_newlyQueuedTimers(nullptr)
	, m_timerCancellationRequested(false)
	, m_shutDownRequested(false)
	, m_thread([this] { this->run(); })
{
}

cppcoro::io_service::timer_thread_state::~timer_thread_state()
{
	m_shutDownRequested.store(true, std::memory_order_release);
	wake_up_timer_thread();
	m_thread.join();
}

void cppcoro::io_service::timer_thread_state::request_timer_cancellation() noexcept
{
	const bool wasTimerCancellationAlreadyRequested =
		m_timerCancellationRequested.exchange(true, std::memory_order_release);
	if (!wasTimerCancellationAlreadyRequested)
	{
		wake_up_timer_thread();
	}
}

void cppcoro::io_service::timer_thread_state::run() noexcept
{
#if CPPCORO_OS_WINNT
	using clock = std::chrono::high_resolution_clock;
	using time_point = clock::time_point;

	timer_queue timerQueue;

	const DWORD waitHandleCount = 2;
	const HANDLE waitHandles[waitHandleCount] =
	{
		m_wakeUpEvent.handle(),
		m_waitableTimerEvent.handle()
	};

	time_point lastSetWaitEventTime = time_point::max();

	timed_schedule_operation* timersReadyToResume = nullptr;

	DWORD timeout = INFINITE;
	while (!m_shutDownRequested.load(std::memory_order_relaxed))
	{
		const DWORD waitResult = ::WaitForMultipleObjectsEx(
			waitHandleCount,
			waitHandles,
			FALSE, // waitAll
			timeout,
			FALSE); // alertable
		if (waitResult == WAIT_OBJECT_0 || waitResult == WAIT_FAILED)
		{
			// Wake-up event (WAIT_OBJECT_0)
			//
			// We are only woken up for:
			// - handling timer cancellation
			// - handling newly queued timers
			// - shutdown
			//
			// We also handle WAIT_FAILED here so that we remain responsive
			// to new timers and cancellation even if the OS fails to perform
			// the wait operation for some reason.

			// Handle cancelled timers
			if (m_timerCancellationRequested.exchange(false, std::memory_order_acquire))
			{
				timerQueue.remove_cancelled_timers(timersReadyToResume);
			}

			// Handle newly queued timers
			auto* newTimers = m_newlyQueuedTimers.exchange(nullptr, std::memory_order_acquire);
			while (newTimers != nullptr)
			{
				auto* timer = newTimers;
				newTimers = timer->m_next;

				if (timer->m_cancellationToken.is_cancellation_requested())
				{
					timer->m_next = timersReadyToResume;
					timersReadyToResume = timer;
				}
				else
				{
					timerQueue.enqueue_timer(timer);
				}
			}
		}
		else if (waitResult == (WAIT_OBJECT_0 + 1))
		{
			lastSetWaitEventTime = time_point::max();
		}

		if (!timerQueue.is_empty())
		{
			time_point currentTime = clock::now();

			timerQueue.dequeue_due_timers(currentTime, timersReadyToResume);

			if (!timerQueue.is_empty())
			{
				auto earliestDueTime = timerQueue.earliest_due_time();
				assert(earliestDueTime > currentTime);

				// Set the waitable timer before trying to schedule any of the ready-to-run
				// timers to avoid the concept of 'current time' on which we calculate the
				// amount of time to wait until the next timer is ready.
				if (earliestDueTime != lastSetWaitEventTime)
				{
					using ticks = std::chrono::duration<LONGLONG, std::ratio<1, 10'000'000>>;

					auto timeUntilNextDueTime = earliestDueTime - currentTime;

					// Negative value indicates relative time.
					LARGE_INTEGER dueTime;
					dueTime.QuadPart = -std::chrono::duration_cast<ticks>(timeUntilNextDueTime).count();

					// Period of 0 indicates no repeat on the timer.
					const LONG period = 0;

					// Don't wake the system from a suspended state just to
					// raise the timer event.
					const BOOL resumeFromSuspend = FALSE;

					const BOOL ok = ::SetWaitableTimer(
						m_waitableTimerEvent.handle(),
						&dueTime,
						period,
						nullptr,
						nullptr,
						resumeFromSuspend);
					if (ok)
					{
						lastSetWaitEventTime = earliestDueTime;
						timeout = INFINITE;
					}
					else
					{
						// Not sure what could cause the call to SetWaitableTimer()
						// to fail here but we'll just try falling back to using
						// the timeout parameter of the WaitForMultipleObjects() call.
						//
						// wake-up at least once every second and retry setting
						// the timer at that point.
						using namespace std::literals::chrono_literals;
						if (timeUntilNextDueTime > 1s)
						{
							timeout = 1000;
						}
						else if (timeUntilNextDueTime > 1ms)
						{
							timeout = static_cast<DWORD>(
								std::chrono::duration_cast<std::chrono::milliseconds>(
									timeUntilNextDueTime).count());
						}
						else
						{
							timeout = 1;
						}
					}
				}
			}
		}

		// Now schedule any ready-to-run timers.
		while (timersReadyToResume != nullptr)
		{
			auto* timer = timersReadyToResume;
			auto* nextTimer = timer->m_next;

			// Use 'release' memory order to ensure that any prior writes to
			// m_next "happen before" any potential uses of that same memory
			// back on the thread that is executing timed_schedule_operation::await_suspend()
			// which has the synchronising 'acquire' semantics.
			if (timer->m_refCount.fetch_sub(1, std::memory_order_release) == 1)
			{
				timer->m_scheduleOperation.m_service.schedule_impl(
					&timer->m_scheduleOperation);
			}

			timersReadyToResume = nextTimer;
		}
	}
#endif
}

void cppcoro::io_service::timer_thread_state::wake_up_timer_thread() noexcept
{
#if CPPCORO_OS_WINNT
	(void)::SetEvent(m_wakeUpEvent.handle());
#endif
}

void cppcoro::io_service::schedule_operation::await_suspend(
	std::coroutine_handle<> awaiter) noexcept
{
	m_awaiter = awaiter;
	m_service.schedule_impl(this);
}

cppcoro::io_service::timed_schedule_operation::timed_schedule_operation(
	io_service& service,
	std::chrono::high_resolution_clock::time_point resumeTime,
	cppcoro::cancellation_token cancellationToken) noexcept
	: m_scheduleOperation(service)
	, m_resumeTime(resumeTime)
	, m_cancellationToken(std::move(cancellationToken))
	, m_refCount(2)
{
}

cppcoro::io_service::timed_schedule_operation::timed_schedule_operation(
	timed_schedule_operation&& other) noexcept
	: m_scheduleOperation(std::move(other.m_scheduleOperation))
	, m_resumeTime(std::move(other.m_resumeTime))
	, m_cancellationToken(std::move(other.m_cancellationToken))
	, m_refCount(2)
{
}

cppcoro::io_service::timed_schedule_operation::~timed_schedule_operation()
{
}

bool cppcoro::io_service::timed_schedule_operation::await_ready() const noexcept
{
	return m_cancellationToken.is_cancellation_requested();
}

void cppcoro::io_service::timed_schedule_operation::await_suspend(
	std::coroutine_handle<> awaiter)
{
	m_scheduleOperation.m_awaiter = awaiter;

	auto& service = m_scheduleOperation.m_service;

	// Ensure the timer state is initialised and the timer thread started.
	auto* timerState = service.ensure_timer_thread_started();

	if (m_cancellationToken.can_be_cancelled())
	{
		m_cancellationRegistration.emplace(m_cancellationToken, [timerState]
		{
			timerState->request_timer_cancellation();
		});
	}

	// Queue the timer schedule to the queue of incoming new timers.
	//
	// We need to do a careful dance here because it could be possible
	// that immediately after queueing the timer this thread could be
	// context-switched out, the timer thread could pick it up and
	// schedule it to be resumed, it could be resumed on an I/O thread
	// and complete its work and the io_service could be destructed.
	// All before we get to execute timerState.wake_up_timer_thread()
	// below. To work around this race we use a reference-counter
	// with initial value 2 and have both the timer thread and this
	// thread decrement the count once the awaiter is ready to be
	// rescheduled. Whichever thread decrements the ref-count to 0
	// is responsible for scheduling the awaiter for resumption.


	// Not sure if we need 'acquire' semantics on this load and
	// on the failure-case of the compare_exchange below.
	//
	// It could potentially be made 'release' if we can guarantee
	// that a read-with 'acquire' semantics in the timer thread
	// of the latest value will synchronise with all prior writes
	// to that value that used 'release' semantics.
	auto* prev = timerState->m_newlyQueuedTimers.load(std::memory_order_acquire);
	do
	{
		m_next = prev;
	} while (!timerState->m_newlyQueuedTimers.compare_exchange_weak(
		prev,
		this,
		std::memory_order_release,
		std::memory_order_acquire));

	if (prev == nullptr)
	{
		timerState->wake_up_timer_thread();
	}

	// Use 'acquire' semantics here to synchronise with the 'release'
	// operation performed on the timer thread to ensure that we have
	// seen all potential writes to this object. Without this, it's
	// possible that a write to the m_next field by the timer thread
	// will race with subsequent writes to that same memory by this
	// thread or whatever I/O thread resumes the coroutine.
	if (m_refCount.fetch_sub(1, std::memory_order_acquire) == 1)
	{
		service.schedule_impl(&m_scheduleOperation);
	}
}

void cppcoro::io_service::timed_schedule_operation::await_resume()
{
	m_cancellationRegistration.reset();
	m_cancellationToken.throw_if_cancellation_requested();
}
