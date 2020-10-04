///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_READABLE_FILE_HPP_INCLUDED
#define CPPCORO_READABLE_FILE_HPP_INCLUDED

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

namespace cppcoro
{
	class readable_file : virtual public file
	{
	public:

		/// Read some data from the file.
		///
		/// Reads \a byteCount bytes from the file starting at \a offset
		/// into the specified \a buffer.
		///
		/// \param offset
		/// The offset within the file to start reading from.
		/// If the file has been opened using file_buffering_mode::unbuffered
		/// then the offset must be a multiple of the file-system's sector size.
		///
		/// \param buffer
		/// The buffer to read the file contents into.
		/// If the file has been opened using file_buffering_mode::unbuffered
		/// then the address of the start of the buffer must be a multiple of
		/// the file-system's sector size.
		///
		/// \param byteCount
		/// The number of bytes to read from the file.
		/// If the file has been opeend using file_buffering_mode::unbuffered
		/// then the byteCount must be a multiple of the file-system's sector size.
		///
		/// \param ct
		/// An optional cancellation_token that can be used to cancel the
		/// read operation before it completes.
		///
		/// \return
		/// An object that represents the read-operation.
		/// This object must be co_await'ed to start the read operation.
		[[nodiscard]]
		file_read_operation read(
			std::uint64_t offset,
			void* buffer,
			std::size_t byteCount) const noexcept;
		[[nodiscard]]
		file_read_operation_cancellable read(
			std::uint64_t offset,
			void* buffer,
			std::size_t byteCount,
			cancellation_token ct) const noexcept;

	protected:

		using file::file;

	};
}

#endif
