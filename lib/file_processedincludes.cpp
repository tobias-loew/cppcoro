///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

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

#include <system_error>
#include <cassert>

#if CPPCORO_OS_WINNT
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <Windows.h>
#endif

cppcoro::file::~file()
{}

std::uint64_t cppcoro::file::size() const
{
#if CPPCORO_OS_WINNT
	LARGE_INTEGER size;
	BOOL ok = ::GetFileSizeEx(m_fileHandle.handle(), &size);
	if (!ok)
	{
		DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category(),
			"error getting file size: GetFileSizeEx"
		};
	}

	return size.QuadPart;
#endif
}

cppcoro::file::file(detail::win32::safe_handle&& fileHandle) noexcept
	: m_fileHandle(std::move(fileHandle))
{
}

cppcoro::detail::win32::safe_handle cppcoro::file::open(
	detail::win32::dword_t fileAccess,
	io_service& ioService,
	const std::filesystem::path& path,
	file_open_mode openMode,
	file_share_mode shareMode,
	file_buffering_mode bufferingMode)
{
	DWORD flags = FILE_FLAG_OVERLAPPED;
	if ((bufferingMode & file_buffering_mode::random_access) == file_buffering_mode::random_access)
	{
		flags |= FILE_FLAG_RANDOM_ACCESS;
	}
	if ((bufferingMode & file_buffering_mode::sequential) == file_buffering_mode::sequential)
	{
		flags |= FILE_FLAG_SEQUENTIAL_SCAN;
	}
	if ((bufferingMode & file_buffering_mode::write_through) == file_buffering_mode::write_through)
	{
		flags |= FILE_FLAG_WRITE_THROUGH;
	}
	if ((bufferingMode & file_buffering_mode::temporary) == file_buffering_mode::temporary)
	{
		flags |= FILE_ATTRIBUTE_TEMPORARY;
	}
	if ((bufferingMode & file_buffering_mode::unbuffered) == file_buffering_mode::unbuffered)
	{
		flags |= FILE_FLAG_NO_BUFFERING;
	}

	DWORD shareFlags = 0;
	if ((shareMode & file_share_mode::read) == file_share_mode::read)
	{
		shareFlags |= FILE_SHARE_READ;
	}
	if ((shareMode & file_share_mode::write) == file_share_mode::write)
	{
		shareFlags |= FILE_SHARE_WRITE;
	}
	if ((shareMode & file_share_mode::delete_) == file_share_mode::delete_)
	{
		shareFlags |= FILE_SHARE_DELETE;
	}

	DWORD creationDisposition = 0;
	switch (openMode)
	{
	case file_open_mode::create_or_open:
		creationDisposition = OPEN_ALWAYS;
		break;
	case file_open_mode::create_always:
		creationDisposition = CREATE_ALWAYS;
		break;
	case file_open_mode::create_new:
		creationDisposition = CREATE_NEW;
		break;
	case file_open_mode::open_existing:
		creationDisposition = OPEN_EXISTING;
		break;
	case file_open_mode::truncate_existing:
		creationDisposition = TRUNCATE_EXISTING;
		break;
	}

	// Open the file
	detail::win32::safe_handle fileHandle(
		::CreateFileW(
			path.wstring().c_str(),
			fileAccess,
			shareFlags,
			nullptr,
			creationDisposition,
			flags,
			nullptr));
	if (fileHandle.handle() == INVALID_HANDLE_VALUE)
	{
		const DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category(),
			"error opening file: CreateFileW"
		};
	}

	// Associate with the I/O service's completion port.
	const HANDLE result = ::CreateIoCompletionPort(
		fileHandle.handle(),
		ioService.native_iocp_handle(),
		0,
		0);
	if (result == nullptr)
	{
		const DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category(),
			"error opening file: CreateIoCompletionPort"
		};
	}

	// Configure I/O operations to avoid dispatching a completion event
	// to the I/O service if the operation completes synchronously.
	// This avoids unnecessary suspension/resuption of the awaiting coroutine.
	const BOOL ok = ::SetFileCompletionNotificationModes(
		fileHandle.handle(),
		FILE_SKIP_COMPLETION_PORT_ON_SUCCESS |
		FILE_SKIP_SET_EVENT_ON_HANDLE);
	if (!ok)
	{
		const DWORD errorCode = ::GetLastError();
		throw std::system_error
		{
			static_cast<int>(errorCode),
			std::system_category(),
			"error opening file: SetFileCompletionNotificationModes"
		};
	}

	return std::move(fileHandle);
}
