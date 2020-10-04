///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_FILE_READ_OPERATION_HPP_INCLUDED
#define CPPCORO_FILE_READ_OPERATION_HPP_INCLUDED

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

#include <atomic>
#include <optional>
#include <coroutine>

#if CPPCORO_OS_WINNT
# include <cppcoro/detail/win32.hpp>
# include <cppcoro/detail/win32_overlapped_operation.hpp>

namespace cppcoro
{
	class file_read_operation_impl
	{
	public:

		file_read_operation_impl(
			detail::win32::handle_t fileHandle,
			void* buffer,
			std::size_t byteCount) noexcept
			: m_fileHandle(fileHandle)
			, m_buffer(buffer)
			, m_byteCount(byteCount)
		{}

		bool try_start(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;
		void cancel(cppcoro::detail::win32_overlapped_operation_base& operation) noexcept;

	private:

		detail::win32::handle_t m_fileHandle;
		void* m_buffer;
		std::size_t m_byteCount;

	};

	class file_read_operation
		: public cppcoro::detail::win32_overlapped_operation<file_read_operation>
	{
	public:

		file_read_operation(
			detail::win32::handle_t fileHandle,
			std::uint64_t fileOffset,
			void* buffer,
			std::size_t byteCount) noexcept
			: cppcoro::detail::win32_overlapped_operation<file_read_operation>(fileOffset)
			, m_impl(fileHandle, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation<file_read_operation>;

		bool try_start() noexcept { return m_impl.try_start(*this); }

		file_read_operation_impl m_impl;

	};

	class file_read_operation_cancellable
		: public cppcoro::detail::win32_overlapped_operation_cancellable<file_read_operation_cancellable>
	{
	public:

		file_read_operation_cancellable(
			detail::win32::handle_t fileHandle,
			std::uint64_t fileOffset,
			void* buffer,
			std::size_t byteCount,
			cancellation_token&& cancellationToken) noexcept
			: cppcoro::detail::win32_overlapped_operation_cancellable<file_read_operation_cancellable>(
				fileOffset, std::move(cancellationToken))
			, m_impl(fileHandle, buffer, byteCount)
		{}

	private:

		friend class cppcoro::detail::win32_overlapped_operation_cancellable<file_read_operation_cancellable>;

		bool try_start() noexcept { return m_impl.try_start(*this); }
		void cancel() noexcept { m_impl.cancel(*this); }

		file_read_operation_impl m_impl;

	};

#endif
}

#endif

#if CPPCORO_OS_WINNT
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <Windows.h>

bool cppcoro::file_read_operation_impl::try_start(
	cppcoro::detail::win32_overlapped_operation_base& operation) noexcept
{
	const DWORD numberOfBytesToRead =
		m_byteCount <= 0xFFFFFFFF ?
		static_cast<DWORD>(m_byteCount) : DWORD(0xFFFFFFFF);

	DWORD numberOfBytesRead = 0;
	BOOL ok = ::ReadFile(
		m_fileHandle,
		m_buffer,
		numberOfBytesToRead,
		&numberOfBytesRead,
		operation.get_overlapped());
	const DWORD errorCode = ok ? ERROR_SUCCESS : ::GetLastError();
	if (errorCode != ERROR_IO_PENDING)
	{
		// Completed synchronously.
		//
		// We are assuming that the file-handle has been set to the
		// mode where synchronous completions do not post a completion
		// event to the I/O completion port and thus can return without
		// suspending here.

		operation.m_errorCode = errorCode;
		operation.m_numberOfBytesTransferred = numberOfBytesRead;

		return false;
	}

	return true;
}

void cppcoro::file_read_operation_impl::cancel(
	cppcoro::detail::win32_overlapped_operation_base& operation) noexcept
{
	(void)::CancelIoEx(m_fileHandle, operation.get_overlapped());
}

#endif // CPPCORO_OS_WINNT
