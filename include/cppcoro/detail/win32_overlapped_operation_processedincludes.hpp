///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_WIN32_OVERLAPPED_OPERATION_HPP_INCLUDED
#define CPPCORO_DETAIL_WIN32_OVERLAPPED_OPERATION_HPP_INCLUDED

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
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_OPERATION_CANCELLED_HPP_INCLUDED
#define CPPCORO_OPERATION_CANCELLED_HPP_INCLUDED

#include <exception>

namespace cppcoro
{
	class operation_cancelled : public std::exception
	{
	public:

		operation_cancelled() noexcept
			: std::exception()
		{}

		const char* what() const noexcept override { return "operation cancelled"; }
	};
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_WIN32_HPP_INCLUDED
#define CPPCORO_DETAIL_WIN32_HPP_INCLUDED

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

#if !CPPCORO_OS_WINNT
# error <cppcoro/detail/win32.hpp> is only supported on the Windows platform.
#endif

#include <utility>
#include <cstdint>

struct _OVERLAPPED;

namespace cppcoro
{
	namespace detail
	{
		namespace win32
		{
			using handle_t = void*;
			using ulongptr_t = std::uintptr_t;
			using longptr_t = std::intptr_t;
			using dword_t = unsigned long;
			using socket_t = std::uintptr_t;
			using ulong_t = unsigned long;

#if CPPCORO_COMPILER_MSVC
# pragma warning(push)
# pragma warning(disable : 4201) // Non-standard anonymous struct/union
#endif

			/// Structure needs to correspond exactly to the builtin
			/// _OVERLAPPED structure from Windows.h.
			struct overlapped
			{
				ulongptr_t Internal;
				ulongptr_t InternalHigh;
				union
				{
					struct
					{
						dword_t Offset;
						dword_t OffsetHigh;
					};
					void* Pointer;
				};
				handle_t hEvent;
			};

#if CPPCORO_COMPILER_MSVC
# pragma warning(pop)
#endif

			struct wsabuf
			{
				constexpr wsabuf() noexcept
					: len(0)
					, buf(nullptr)
				{}

				constexpr wsabuf(void* ptr, std::size_t size)
					: len(size <= ulong_t(-1) ? ulong_t(size) : ulong_t(-1))
					, buf(static_cast<char*>(ptr))
				{}

				ulong_t len;
				char* buf;
			};

			struct io_state : win32::overlapped
			{
				using callback_type = void(
					io_state* state,
					win32::dword_t errorCode,
					win32::dword_t numberOfBytesTransferred,
					win32::ulongptr_t completionKey);

				io_state(callback_type* callback = nullptr) noexcept
					: io_state(std::uint64_t(0), callback)
				{}

				io_state(void* pointer, callback_type* callback) noexcept
					: m_callback(callback)
				{
					this->Internal = 0;
					this->InternalHigh = 0;
					this->Pointer = pointer;
					this->hEvent = nullptr;
				}

				io_state(std::uint64_t offset, callback_type* callback) noexcept
					: m_callback(callback)
				{
					this->Internal = 0;
					this->InternalHigh = 0;
					this->Offset = static_cast<dword_t>(offset);
					this->OffsetHigh = static_cast<dword_t>(offset >> 32);
					this->hEvent = nullptr;
				}

				callback_type* m_callback;
			};

			class safe_handle
			{
			public:

				safe_handle()
					: m_handle(nullptr)
				{}

				explicit safe_handle(handle_t handle)
					: m_handle(handle)
				{}

				safe_handle(const safe_handle& other) = delete;

				safe_handle(safe_handle&& other) noexcept
					: m_handle(other.m_handle)
				{
					other.m_handle = nullptr;
				}

				~safe_handle()
				{
					close();
				}

				safe_handle& operator=(safe_handle handle) noexcept
				{
					swap(handle);
					return *this;
				}

				constexpr handle_t handle() const { return m_handle; }

				/// Calls CloseHandle() and sets the handle to NULL.
				void close() noexcept;

				void swap(safe_handle& other) noexcept
				{
					std::swap(m_handle, other.m_handle);
				}

				bool operator==(const safe_handle& other) const
				{
					return m_handle == other.m_handle;
				}

				bool operator!=(const safe_handle& other) const
				{
					return m_handle != other.m_handle;
				}

				bool operator==(handle_t handle) const
				{
					return m_handle == handle;
				}

				bool operator!=(handle_t handle) const
				{
					return m_handle != handle;
				}

			private:

				handle_t m_handle;

			};
		}
	}
}

#endif

#include <optional>
#include <system_error>
#include <coroutine>
#include <cassert>

namespace cppcoro
{
	namespace detail
	{
		class win32_overlapped_operation_base
			: protected detail::win32::io_state
		{
		public:

			win32_overlapped_operation_base(
				detail::win32::io_state::callback_type* callback) noexcept
				: detail::win32::io_state(callback)
				, m_errorCode(0)
				, m_numberOfBytesTransferred(0)
			{}

			win32_overlapped_operation_base(
				void* pointer,
				detail::win32::io_state::callback_type* callback) noexcept
				: detail::win32::io_state(pointer, callback)
				, m_errorCode(0)
				, m_numberOfBytesTransferred(0)
			{}

			win32_overlapped_operation_base(
				std::uint64_t offset,
				detail::win32::io_state::callback_type* callback) noexcept
				: detail::win32::io_state(offset, callback)
				, m_errorCode(0)
				, m_numberOfBytesTransferred(0)
			{}

			_OVERLAPPED* get_overlapped() noexcept
			{
				return reinterpret_cast<_OVERLAPPED*>(
					static_cast<detail::win32::overlapped*>(this));
			}

			std::size_t get_result()
			{
				if (m_errorCode != 0)
				{
					throw std::system_error{
						static_cast<int>(m_errorCode),
						std::system_category()
					};
				}

				return m_numberOfBytesTransferred;
			}

			detail::win32::dword_t m_errorCode;
			detail::win32::dword_t m_numberOfBytesTransferred;

		};

		template<typename OPERATION>
		class win32_overlapped_operation
			: protected win32_overlapped_operation_base
		{
		protected:

			win32_overlapped_operation() noexcept
				: win32_overlapped_operation_base(
					&win32_overlapped_operation::on_operation_completed)
			{}

			win32_overlapped_operation(void* pointer) noexcept
				: win32_overlapped_operation_base(
					pointer,
					&win32_overlapped_operation::on_operation_completed)
			{}

			win32_overlapped_operation(std::uint64_t offset) noexcept
				: win32_overlapped_operation_base(
					offset,
					&win32_overlapped_operation::on_operation_completed)
			{}

		public:

			bool await_ready() const noexcept { return false; }

			CPPCORO_NOINLINE
			bool await_suspend(std::coroutine_handle<> awaitingCoroutine)
			{
				static_assert(std::is_base_of_v<win32_overlapped_operation, OPERATION>);

				m_awaitingCoroutine = awaitingCoroutine;
				return static_cast<OPERATION*>(this)->try_start();
			}

			decltype(auto) await_resume()
			{
				return static_cast<OPERATION*>(this)->get_result();
			}

		private:

			static void on_operation_completed(
				detail::win32::io_state* ioState,
				detail::win32::dword_t errorCode,
				detail::win32::dword_t numberOfBytesTransferred,
				[[maybe_unused]] detail::win32::ulongptr_t completionKey) noexcept
			{
				auto* operation = static_cast<win32_overlapped_operation*>(ioState);
				operation->m_errorCode = errorCode;
				operation->m_numberOfBytesTransferred = numberOfBytesTransferred;
				operation->m_awaitingCoroutine.resume();
			}

			std::coroutine_handle<> m_awaitingCoroutine;

		};

		template<typename OPERATION>
		class win32_overlapped_operation_cancellable
			: protected win32_overlapped_operation_base
		{
			// ERROR_OPERATION_ABORTED value from <Windows.h>
			static constexpr detail::win32::dword_t error_operation_aborted = 995L;

		protected:

			win32_overlapped_operation_cancellable(cancellation_token&& ct) noexcept
				: win32_overlapped_operation_base(&win32_overlapped_operation_cancellable::on_operation_completed)
				, m_state(ct.is_cancellation_requested() ? state::completed : state::not_started)
				, m_cancellationToken(std::move(ct))
			{
				m_errorCode = error_operation_aborted;
			}

			win32_overlapped_operation_cancellable(
				void* pointer,
				cancellation_token&& ct) noexcept
				: win32_overlapped_operation_base(pointer, &win32_overlapped_operation_cancellable::on_operation_completed)
				, m_state(ct.is_cancellation_requested() ? state::completed : state::not_started)
				, m_cancellationToken(std::move(ct))
			{
				m_errorCode = error_operation_aborted;
			}

			win32_overlapped_operation_cancellable(
				std::uint64_t offset,
				cancellation_token&& ct) noexcept
				: win32_overlapped_operation_base(offset, &win32_overlapped_operation_cancellable::on_operation_completed)
				, m_state(ct.is_cancellation_requested() ? state::completed : state::not_started)
				, m_cancellationToken(std::move(ct))
			{
				m_errorCode = error_operation_aborted;
			}

			win32_overlapped_operation_cancellable(
				win32_overlapped_operation_cancellable&& other) noexcept
				: win32_overlapped_operation_base(std::move(other))
				, m_state(other.m_state.load(std::memory_order_relaxed))
				, m_cancellationToken(std::move(other.m_cancellationToken))
			{
				assert(m_errorCode == other.m_errorCode);
				assert(m_numberOfBytesTransferred == other.m_numberOfBytesTransferred);
			}

		public:

			bool await_ready() const noexcept
			{
				return m_state.load(std::memory_order_relaxed) == state::completed;
			}

			CPPCORO_NOINLINE
			bool await_suspend(std::coroutine_handle<> awaitingCoroutine)
			{
				static_assert(std::is_base_of_v<win32_overlapped_operation_cancellable, OPERATION>);

				m_awaitingCoroutine = awaitingCoroutine;

				// TRICKY: Register cancellation callback before starting the operation
				// in case the callback registration throws due to insufficient
				// memory. We need to make sure that the logic that occurs after
				// starting the operation is noexcept, otherwise we run into the
				// problem of not being able to cancel the started operation and
				// the dilemma of what to do with the exception.
				//
				// However, doing this means that the cancellation callback may run
				// prior to returning below so in the case that cancellation may
				// occur we defer setting the state to 'started' until after
				// the operation has finished starting. The cancellation callback
				// will only attempt to request cancellation of the operation with
				// CancelIoEx() once the state has been set to 'started'.
				const bool canBeCancelled = m_cancellationToken.can_be_cancelled();
				if (canBeCancelled)
				{
					m_cancellationCallback.emplace(
						std::move(m_cancellationToken),
						[this] { this->on_cancellation_requested(); });
				}
				else
				{
					m_state.store(state::started, std::memory_order_relaxed);
				}

				// Now start the operation.
				const bool willCompleteAsynchronously = static_cast<OPERATION*>(this)->try_start();
				if (!willCompleteAsynchronously)
				{
					// Operation completed synchronously, resume awaiting coroutine immediately.
					return false;
				}

				if (canBeCancelled)
				{
					// Need to flag that the operation has finished starting now.

					// However, the operation may have completed concurrently on
					// another thread, transitioning directly from not_started -> complete.
					// Or it may have had the cancellation callback execute and transition
					// from not_started -> cancellation_requested. We use a compare-exchange
					// to determine a winner between these potential racing cases.
					state oldState = state::not_started;
					if (!m_state.compare_exchange_strong(
						oldState,
						state::started,
						std::memory_order_release,
						std::memory_order_acquire))
					{
						if (oldState == state::cancellation_requested)
						{
							// Request the operation be cancelled.
							// Note that it may have already completed on a background
							// thread by now so this request for cancellation may end up
							// being ignored.
							static_cast<OPERATION*>(this)->cancel();

							if (!m_state.compare_exchange_strong(
								oldState,
								state::started,
								std::memory_order_release,
								std::memory_order_acquire))
							{
								assert(oldState == state::completed);
								return false;
							}
						}
						else
						{
							assert(oldState == state::completed);
							return false;
						}
					}
				}

				return true;
			}

			decltype(auto) await_resume()
			{
				// Free memory used by the cancellation callback now that the operation
				// has completed rather than waiting until the operation object destructs.
				// eg. If the operation is passed to when_all() then the operation object
				// may not be destructed until all of the operations complete.
				m_cancellationCallback.reset();

				if (m_errorCode == error_operation_aborted)
				{
					throw operation_cancelled{};
				}

				return static_cast<OPERATION*>(this)->get_result();
			}

		private:

			enum class state
			{
				not_started,
				started,
				cancellation_requested,
				completed
			};

			void on_cancellation_requested() noexcept
			{
				auto oldState = m_state.load(std::memory_order_acquire);
				if (oldState == state::not_started)
				{
					// This callback is running concurrently with await_suspend().
					// The call to start the operation may not have returned yet so
					// we can't safely request cancellation of it. Instead we try to
					// notify the await_suspend() thread by transitioning the state
					// to state::cancellation_requested so that the await_suspend()
					// thread can request cancellation after it has finished starting
					// the operation.
					const bool transferredCancelResponsibility =
						m_state.compare_exchange_strong(
							oldState,
							state::cancellation_requested,
							std::memory_order_release,
							std::memory_order_acquire);
					if (transferredCancelResponsibility)
					{
						return;
					}
				}

				// No point requesting cancellation if the operation has already completed.
				if (oldState != state::completed)
				{
					static_cast<OPERATION*>(this)->cancel();
				}
			}

			static void on_operation_completed(
				detail::win32::io_state* ioState,
				detail::win32::dword_t errorCode,
				detail::win32::dword_t numberOfBytesTransferred,
				[[maybe_unused]] detail::win32::ulongptr_t completionKey) noexcept
			{
				auto* operation = static_cast<win32_overlapped_operation_cancellable*>(ioState);

				operation->m_errorCode = errorCode;
				operation->m_numberOfBytesTransferred = numberOfBytesTransferred;

				auto state = operation->m_state.load(std::memory_order_acquire);
				if (state == state::started)
				{
					operation->m_state.store(state::completed, std::memory_order_relaxed);
					operation->m_awaitingCoroutine.resume();
				}
				else
				{
					// We are racing with await_suspend() call suspending.
					// Try to mark it as completed using an atomic exchange and look
					// at the previous value to determine whether the coroutine suspended
					// first (in which case we resume it now) or we marked it as completed
					// first (in which case await_suspend() will return false and immediately
					// resume the coroutine).
					state = operation->m_state.exchange(
						state::completed,
						std::memory_order_acq_rel);
					if (state == state::started)
					{
						// The await_suspend() method returned (or will return) 'true' and so
						// we need to resume the coroutine.
						operation->m_awaitingCoroutine.resume();
					}
				}
			}

			std::atomic<state> m_state;
			cppcoro::cancellation_token m_cancellationToken;
			std::optional<cppcoro::cancellation_registration> m_cancellationCallback;
			std::coroutine_handle<> m_awaitingCoroutine;

		};
	}
}

#endif
