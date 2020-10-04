///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_SHARED_LAZY_TASK_HPP_INCLUDED
#define CPPCORO_SHARED_LAZY_TASK_HPP_INCLUDED

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
#ifndef CPPCORO_AWAITABLE_TRAITS_HPP_INCLUDED
#define CPPCORO_AWAITABLE_TRAITS_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_GET_AWAITER_HPP_INCLUDED
#define CPPCORO_DETAIL_GET_AWAITER_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_IS_AWAITER_HPP_INCLUDED
#define CPPCORO_DETAIL_IS_AWAITER_HPP_INCLUDED

#include <type_traits>
#include <coroutine>

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct is_coroutine_handle
			: std::false_type
		{};

		template<typename PROMISE>
		struct is_coroutine_handle<std::coroutine_handle<PROMISE>>
			: std::true_type
		{};

		// NOTE: We're accepting a return value of coroutine_handle<P> here
		// which is an extension supported by Clang which is not yet part of
		// the C++ coroutines TS.
		template<typename T>
		struct is_valid_await_suspend_return_value : std::disjunction<
			std::is_void<T>,
			std::is_same<T, bool>,
			is_coroutine_handle<T>>
		{};

		template<typename T, typename = std::void_t<>>
		struct is_awaiter : std::false_type {};

		// NOTE: We're testing whether await_suspend() will be callable using an
		// arbitrary coroutine_handle here by checking if it supports being passed
		// a coroutine_handle<void>. This may result in a false-result for some
		// types which are only awaitable within a certain context.
		template<typename T>
		struct is_awaiter<T, std::void_t<
			decltype(std::declval<T>().await_ready()),
			decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>())),
			decltype(std::declval<T>().await_resume())>> :
			std::conjunction<
				std::is_constructible<bool, decltype(std::declval<T>().await_ready())>,
				detail::is_valid_await_suspend_return_value<
					decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>()))>>
		{};
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_ANY_HPP_INCLUDED
#define CPPCORO_DETAIL_ANY_HPP_INCLUDED

namespace cppcoro
{
	namespace detail
	{
		// Helper type that can be cast-to from any type.
		struct any
		{
			template<typename T>
			any(T&&) noexcept
			{}
		};
	}
}

#endif

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		auto get_awaiter_impl(T&& value, int)
			noexcept(noexcept(static_cast<T&&>(value).operator co_await()))
			-> decltype(static_cast<T&&>(value).operator co_await())
		{
			return static_cast<T&&>(value).operator co_await();
		}

		template<typename T>
		auto get_awaiter_impl(T&& value, long)
			noexcept(noexcept(operator co_await(static_cast<T&&>(value))))
			-> decltype(operator co_await(static_cast<T&&>(value)))
		{
			return operator co_await(static_cast<T&&>(value));
		}

		template<
			typename T,
			std::enable_if_t<cppcoro::detail::is_awaiter<T&&>::value, int> = 0>
		T&& get_awaiter_impl(T&& value, cppcoro::detail::any) noexcept
		{
			return static_cast<T&&>(value);
		}

		template<typename T>
		auto get_awaiter(T&& value)
			noexcept(noexcept(detail::get_awaiter_impl(static_cast<T&&>(value), 123)))
			-> decltype(detail::get_awaiter_impl(static_cast<T&&>(value), 123))
		{
			return detail::get_awaiter_impl(static_cast<T&&>(value), 123);
		}
	}
}

#endif

#include <type_traits>

namespace cppcoro
{
	template<typename T, typename = void>
	struct awaitable_traits
	{};

	template<typename T>
	struct awaitable_traits<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
	{
		using awaiter_t = decltype(cppcoro::detail::get_awaiter(std::declval<T>()));

		using await_result_t = decltype(std::declval<awaiter_t>().await_resume());
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_BROKEN_PROMISE_HPP_INCLUDED
#define CPPCORO_BROKEN_PROMISE_HPP_INCLUDED

#include <stdexcept>

namespace cppcoro
{
	/// \brief
	/// Exception thrown when you attempt to retrieve the result of
	/// a task that has been detached from its promise/coroutine.
	class broken_promise : public std::logic_error
	{
	public:
		broken_promise()
			: std::logic_error("broken promise")
		{}
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_TASK_HPP_INCLUDED
#define CPPCORO_TASK_HPP_INCLUDED

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
#ifndef CPPCORO_AWAITABLE_TRAITS_HPP_INCLUDED
#define CPPCORO_AWAITABLE_TRAITS_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_GET_AWAITER_HPP_INCLUDED
#define CPPCORO_DETAIL_GET_AWAITER_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_IS_AWAITER_HPP_INCLUDED
#define CPPCORO_DETAIL_IS_AWAITER_HPP_INCLUDED

#include <type_traits>
#include <coroutine>

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct is_coroutine_handle
			: std::false_type
		{};

		template<typename PROMISE>
		struct is_coroutine_handle<std::coroutine_handle<PROMISE>>
			: std::true_type
		{};

		// NOTE: We're accepting a return value of coroutine_handle<P> here
		// which is an extension supported by Clang which is not yet part of
		// the C++ coroutines TS.
		template<typename T>
		struct is_valid_await_suspend_return_value : std::disjunction<
			std::is_void<T>,
			std::is_same<T, bool>,
			is_coroutine_handle<T>>
		{};

		template<typename T, typename = std::void_t<>>
		struct is_awaiter : std::false_type {};

		// NOTE: We're testing whether await_suspend() will be callable using an
		// arbitrary coroutine_handle here by checking if it supports being passed
		// a coroutine_handle<void>. This may result in a false-result for some
		// types which are only awaitable within a certain context.
		template<typename T>
		struct is_awaiter<T, std::void_t<
			decltype(std::declval<T>().await_ready()),
			decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>())),
			decltype(std::declval<T>().await_resume())>> :
			std::conjunction<
				std::is_constructible<bool, decltype(std::declval<T>().await_ready())>,
				detail::is_valid_await_suspend_return_value<
					decltype(std::declval<T>().await_suspend(std::declval<std::coroutine_handle<>>()))>>
		{};
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_ANY_HPP_INCLUDED
#define CPPCORO_DETAIL_ANY_HPP_INCLUDED

namespace cppcoro
{
	namespace detail
	{
		// Helper type that can be cast-to from any type.
		struct any
		{
			template<typename T>
			any(T&&) noexcept
			{}
		};
	}
}

#endif

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		auto get_awaiter_impl(T&& value, int)
			noexcept(noexcept(static_cast<T&&>(value).operator co_await()))
			-> decltype(static_cast<T&&>(value).operator co_await())
		{
			return static_cast<T&&>(value).operator co_await();
		}

		template<typename T>
		auto get_awaiter_impl(T&& value, long)
			noexcept(noexcept(operator co_await(static_cast<T&&>(value))))
			-> decltype(operator co_await(static_cast<T&&>(value)))
		{
			return operator co_await(static_cast<T&&>(value));
		}

		template<
			typename T,
			std::enable_if_t<cppcoro::detail::is_awaiter<T&&>::value, int> = 0>
		T&& get_awaiter_impl(T&& value, cppcoro::detail::any) noexcept
		{
			return static_cast<T&&>(value);
		}

		template<typename T>
		auto get_awaiter(T&& value)
			noexcept(noexcept(detail::get_awaiter_impl(static_cast<T&&>(value), 123)))
			-> decltype(detail::get_awaiter_impl(static_cast<T&&>(value), 123))
		{
			return detail::get_awaiter_impl(static_cast<T&&>(value), 123);
		}
	}
}

#endif

#include <type_traits>

namespace cppcoro
{
	template<typename T, typename = void>
	struct awaitable_traits
	{};

	template<typename T>
	struct awaitable_traits<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
	{
		using awaiter_t = decltype(cppcoro::detail::get_awaiter(std::declval<T>()));

		using await_result_t = decltype(std::declval<awaiter_t>().await_resume());
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_BROKEN_PROMISE_HPP_INCLUDED
#define CPPCORO_BROKEN_PROMISE_HPP_INCLUDED

#include <stdexcept>

namespace cppcoro
{
	/// \brief
	/// Exception thrown when you attempt to retrieve the result of
	/// a task that has been detached from its promise/coroutine.
	class broken_promise : public std::logic_error
	{
	public:
		broken_promise()
			: std::logic_error("broken promise")
		{}
	};
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_REMOVE_RVALUE_REFERENCE_HPP_INCLUDED
#define CPPCORO_DETAIL_REMOVE_RVALUE_REFERENCE_HPP_INCLUDED

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct remove_rvalue_reference
		{
			using type = T;
		};

		template<typename T>
		struct remove_rvalue_reference<T&&>
		{
			using type = T;
		};

		template<typename T>
		using remove_rvalue_reference_t = typename remove_rvalue_reference<T>::type;
	}
}

#endif

#include <atomic>
#include <exception>
#include <utility>
#include <type_traits>
#include <cstdint>
#include <cassert>

#include <coroutine>

namespace cppcoro
{
	template<typename T> class task;

	namespace detail
	{
		class task_promise_base
		{
			friend struct final_awaitable;

			struct final_awaitable
			{
				bool await_ready() const noexcept { return false; }

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
				template<typename PROMISE>
				std::coroutine_handle<> await_suspend(
					std::coroutine_handle<PROMISE> coro) noexcept
				{
					return coro.promise().m_continuation;
				}
#else
				// HACK: Need to add CPPCORO_NOINLINE to await_suspend() method
				// to avoid MSVC 2017.8 from spilling some local variables in
				// await_suspend() onto the coroutine frame in some cases.
				// Without this, some tests in async_auto_reset_event_tests.cpp
				// were crashing under x86 optimised builds.
				template<typename PROMISE>
				CPPCORO_NOINLINE
				void await_suspend(std::coroutine_handle<PROMISE> coroutine)
				{
					task_promise_base& promise = coroutine.promise();

					// Use 'release' memory semantics in case we finish before the
					// awaiter can suspend so that the awaiting thread sees our
					// writes to the resulting value.
					// Use 'acquire' memory semantics in case the caller registered
					// the continuation before we finished. Ensure we see their write
					// to m_continuation.
					if (promise.m_state.exchange(true, std::memory_order_acq_rel))
					{
						promise.m_continuation.resume();
					}
				}
#endif

				void await_resume() noexcept {}
			};

		public:

			task_promise_base() noexcept
#if !CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
				: m_state(false)
#endif
			{}

			auto initial_suspend() noexcept
			{
				return std::suspend_always{};
			}

			auto final_suspend() noexcept
			{
				return final_awaitable{};
			}

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			void set_continuation(std::coroutine_handle<> continuation) noexcept
			{
				m_continuation = continuation;
			}
#else
			bool try_set_continuation(std::coroutine_handle<> continuation)
			{
				m_continuation = continuation;
				return !m_state.exchange(true, std::memory_order_acq_rel);
			}
#endif

		private:

			std::coroutine_handle<> m_continuation;

#if !CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			// Initially false. Set to true when either a continuation is registered
			// or when the coroutine has run to completion. Whichever operation
			// successfully transitions from false->true got there first.
			std::atomic<bool> m_state;
#endif

		};

		template<typename T>
		class task_promise final : public task_promise_base
		{
		public:

			task_promise() noexcept {}

			~task_promise()
			{
				switch (m_resultType)
				{
				case result_type::value:
					m_value.~T();
					break;
				case result_type::exception:
					m_exception.~exception_ptr();
					break;
				default:
					break;
				}
			}

			task<T> get_return_object() noexcept;

			void unhandled_exception() noexcept
			{
				::new (static_cast<void*>(std::addressof(m_exception))) std::exception_ptr(
					std::current_exception());
				m_resultType = result_type::exception;
			}

			template<
				typename VALUE,
				typename = std::enable_if_t<std::is_convertible_v<VALUE&&, T>>>
			void return_value(VALUE&& value)
				noexcept(std::is_nothrow_constructible_v<T, VALUE&&>)
			{
				::new (static_cast<void*>(std::addressof(m_value))) T(std::forward<VALUE>(value));
				m_resultType = result_type::value;
			}

			T& result() &
			{
				if (m_resultType == result_type::exception)
				{
					std::rethrow_exception(m_exception);
				}

				assert(m_resultType == result_type::value);

				return m_value;
			}

			// HACK: Need to have co_await of task<int> return prvalue rather than
			// rvalue-reference to work around an issue with MSVC where returning
			// rvalue reference of a fundamental type from await_resume() will
			// cause the value to be copied to a temporary. This breaks the
			// sync_wait() implementation.
			// See https://github.com/lewissbaker/cppcoro/issues/40#issuecomment-326864107
			using rvalue_type = std::conditional_t<
				std::is_arithmetic_v<T> || std::is_pointer_v<T>,
				T,
				T&&>;

			rvalue_type result() &&
			{
				if (m_resultType == result_type::exception)
				{
					std::rethrow_exception(m_exception);
				}

				assert(m_resultType == result_type::value);

				return std::move(m_value);
			}

		private:

			enum class result_type { empty, value, exception };

			result_type m_resultType = result_type::empty;

			union
			{
				T m_value;
				std::exception_ptr m_exception;
			};

		};

		template<>
		class task_promise<void> : public task_promise_base
		{
		public:

			task_promise() noexcept = default;

			task<void> get_return_object() noexcept;

			void return_void() noexcept
			{}

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}
			}

		private:

			std::exception_ptr m_exception;

		};

		template<typename T>
		class task_promise<T&> : public task_promise_base
		{
		public:

			task_promise() noexcept = default;

			task<T&> get_return_object() noexcept;

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void return_value(T& value) noexcept
			{
				m_value = std::addressof(value);
			}

			T& result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}

				return *m_value;
			}

		private:

			T* m_value = nullptr;
			std::exception_ptr m_exception;

		};
	}

	/// \brief
	/// A task represents an operation that produces a result both lazily
	/// and asynchronously.
	///
	/// When you call a coroutine that returns a task, the coroutine
	/// simply captures any passed parameters and returns exeuction to the
	/// caller. Execution of the coroutine body does not start until the
	/// coroutine is first co_await'ed.
	template<typename T = void>
	class [[nodiscard]] task
	{
	public:

		using promise_type = detail::task_promise<T>;

		using value_type = T;

	private:

		struct awaitable_base
		{
			std::coroutine_handle<promise_type> m_coroutine;

			awaitable_base(std::coroutine_handle<promise_type> coroutine) noexcept
				: m_coroutine(coroutine)
			{}

			bool await_ready() const noexcept
			{
				return !m_coroutine || m_coroutine.done();
			}

#if CPPCORO_COMPILER_SUPPORTS_SYMMETRIC_TRANSFER
			std::coroutine_handle<> await_suspend(
				std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				m_coroutine.promise().set_continuation(awaitingCoroutine);
				return m_coroutine;
			}
#else
			bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				// NOTE: We are using the bool-returning version of await_suspend() here
				// to work around a potential stack-overflow issue if a coroutine
				// awaits many synchronously-completing tasks in a loop.
				//
				// We first start the task by calling resume() and then conditionally
				// attach the continuation if it has not already completed. This allows us
				// to immediately resume the awaiting coroutine without increasing
				// the stack depth, avoiding the stack-overflow problem. However, it has
				// the down-side of requiring a std::atomic to arbitrate the race between
				// the coroutine potentially completing on another thread concurrently
				// with registering the continuation on this thread.
				//
				// We can eliminate the use of the std::atomic once we have access to
				// coroutine_handle-returning await_suspend() on both MSVC and Clang
				// as this will provide ability to suspend the awaiting coroutine and
				// resume another coroutine with a guaranteed tail-call to resume().
				m_coroutine.resume();
				return m_coroutine.promise().try_set_continuation(awaitingCoroutine);
			}
#endif
		};

	public:

		task() noexcept
			: m_coroutine(nullptr)
		{}

		explicit task(std::coroutine_handle<promise_type> coroutine)
			: m_coroutine(coroutine)
		{}

		task(task&& t) noexcept
			: m_coroutine(t.m_coroutine)
		{
			t.m_coroutine = nullptr;
		}

		/// Disable copy construction/assignment.
		task(const task&) = delete;
		task& operator=(const task&) = delete;

		/// Frees resources used by this task.
		~task()
		{
			if (m_coroutine)
			{
				m_coroutine.destroy();
			}
		}

		task& operator=(task&& other) noexcept
		{
			if (std::addressof(other) != this)
			{
				if (m_coroutine)
				{
					m_coroutine.destroy();
				}

				m_coroutine = other.m_coroutine;
				other.m_coroutine = nullptr;
			}

			return *this;
		}

		/// \brief
		/// Query if the task result is complete.
		///
		/// Awaiting a task that is ready is guaranteed not to block/suspend.
		bool is_ready() const noexcept
		{
			return !m_coroutine || m_coroutine.done();
		}

		auto operator co_await() const & noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				decltype(auto) await_resume()
				{
					if (!this->m_coroutine)
					{
						throw broken_promise{};
					}

					return this->m_coroutine.promise().result();
				}
			};

			return awaitable{ m_coroutine };
		}

		auto operator co_await() const && noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				decltype(auto) await_resume()
				{
					if (!this->m_coroutine)
					{
						throw broken_promise{};
					}

					return std::move(this->m_coroutine.promise()).result();
				}
			};

			return awaitable{ m_coroutine };
		}

		/// \brief
		/// Returns an awaitable that will await completion of the task without
		/// attempting to retrieve the result.
		auto when_ready() const noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				void await_resume() const noexcept {}
			};

			return awaitable{ m_coroutine };
		}

	private:

		std::coroutine_handle<promise_type> m_coroutine;

	};

	namespace detail
	{
		template<typename T>
		task<T> task_promise<T>::get_return_object() noexcept
		{
			return task<T>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}

		inline task<void> task_promise<void>::get_return_object() noexcept
		{
			return task<void>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}

		template<typename T>
		task<T&> task_promise<T&>::get_return_object() noexcept
		{
			return task<T&>{ std::coroutine_handle<task_promise>::from_promise(*this) };
		}
	}

	template<typename AWAITABLE>
	auto make_task(AWAITABLE awaitable)
		-> task<detail::remove_rvalue_reference_t<typename awaitable_traits<AWAITABLE>::await_result_t>>
	{
		co_return co_await static_cast<AWAITABLE&&>(awaitable);
	}
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_REMOVE_RVALUE_REFERENCE_HPP_INCLUDED
#define CPPCORO_DETAIL_REMOVE_RVALUE_REFERENCE_HPP_INCLUDED

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct remove_rvalue_reference
		{
			using type = T;
		};

		template<typename T>
		struct remove_rvalue_reference<T&&>
		{
			using type = T;
		};

		template<typename T>
		using remove_rvalue_reference_t = typename remove_rvalue_reference<T>::type;
	}
}

#endif

#include <atomic>
#include <exception>
#include <utility>
#include <type_traits>

#include <coroutine>

namespace cppcoro
{
	template<typename T>
	class shared_task;

	namespace detail
	{
		struct shared_task_waiter
		{
			std::coroutine_handle<> m_continuation;
			shared_task_waiter* m_next;
		};

		class shared_task_promise_base
		{
			friend struct final_awaiter;

			struct final_awaiter
			{
				bool await_ready() const noexcept { return false; }

				template<typename PROMISE>
				void await_suspend(std::coroutine_handle<PROMISE> h) noexcept
				{
					shared_task_promise_base& promise = h.promise();

					// Exchange operation needs to be 'release' so that subsequent awaiters have
					// visibility of the result. Also needs to be 'acquire' so we have visibility
					// of writes to the waiters list.
					void* const valueReadyValue = &promise;
					void* waiters = promise.m_waiters.exchange(valueReadyValue, std::memory_order_acq_rel);
					if (waiters != nullptr)
					{
						shared_task_waiter* waiter = static_cast<shared_task_waiter*>(waiters);
						while (waiter->m_next != nullptr)
						{
							// Read the m_next pointer before resuming the coroutine
							// since resuming the coroutine may destroy the shared_task_waiter value.
							auto* next = waiter->m_next;
							waiter->m_continuation.resume();
							waiter = next;
						}

						// Resume last waiter in tail position to allow it to potentially
						// be compiled as a tail-call.
						waiter->m_continuation.resume();
					}
				}

				void await_resume() noexcept {}
			};

		public:

			shared_task_promise_base() noexcept
				: m_refCount(1)
				, m_waiters(&this->m_waiters)				
				, m_exception(nullptr)
			{}

			std::suspend_always initial_suspend() noexcept { return {}; }
			final_awaiter final_suspend() noexcept { return {}; }

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			bool is_ready() const noexcept
			{
				const void* const valueReadyValue = this;
				return m_waiters.load(std::memory_order_acquire) == valueReadyValue;
			}

			void add_ref() noexcept
			{
				m_refCount.fetch_add(1, std::memory_order_relaxed);
			}

			/// Decrement the reference count.
			///
			/// \return
			/// true if successfully detached, false if this was the last
			/// reference to the coroutine, in which case the caller must
			/// call destroy() on the coroutine handle.
			bool try_detach() noexcept
			{
				return m_refCount.fetch_sub(1, std::memory_order_acq_rel) != 1;
			}

			/// Try to enqueue a waiter to the list of waiters.
			///
			/// \param waiter
			/// Pointer to the state from the waiter object.
			/// Must have waiter->m_coroutine member populated with the coroutine
			/// handle of the awaiting coroutine.
			///
			/// \param coroutine
			/// Coroutine handle for this promise object.
			///
			/// \return
			/// true if the waiter was successfully queued, in which case
			/// waiter->m_coroutine will be resumed when the task completes.
			/// false if the coroutine was already completed and the awaiting
			/// coroutine can continue without suspending.
			bool try_await(shared_task_waiter* waiter, std::coroutine_handle<> coroutine)
			{
				void* const valueReadyValue = this;
				void* const notStartedValue = &this->m_waiters;
				constexpr void* startedNoWaitersValue = static_cast<shared_task_waiter*>(nullptr);

				// NOTE: If the coroutine is not yet started then the first waiter
				// will start the coroutine before enqueuing itself up to the list
				// of suspended waiters waiting for completion. We split this into
				// two steps to allow the first awaiter to return without suspending.
				// This avoids recursively resuming the first waiter inside the call to
				// coroutine.resume() in the case that the coroutine completes
				// synchronously, which could otherwise lead to stack-overflow if
				// the awaiting coroutine awaited many synchronously-completing
				// tasks in a row.

				// Start the coroutine if not already started.
				void* oldWaiters = m_waiters.load(std::memory_order_acquire);
				if (oldWaiters == notStartedValue &&
				    m_waiters.compare_exchange_strong(
				      oldWaiters,
				      startedNoWaitersValue,
				      std::memory_order_relaxed))
				{
					// Start the task executing.
					coroutine.resume();
					oldWaiters = m_waiters.load(std::memory_order_acquire);
				}

				// Enqueue the waiter into the list of waiting coroutines.
				do
				{
					if (oldWaiters == valueReadyValue)
					{
						// Coroutine already completed, don't suspend.
						return false;
					}

					waiter->m_next = static_cast<shared_task_waiter*>(oldWaiters);
				} while (!m_waiters.compare_exchange_weak(
					oldWaiters,
					static_cast<void*>(waiter),
					std::memory_order_release,
					std::memory_order_acquire));

				return true;
			}

		protected:

			bool completed_with_unhandled_exception()
			{
				return m_exception != nullptr;
			}

			void rethrow_if_unhandled_exception()
			{
				if (m_exception != nullptr)
				{
					std::rethrow_exception(m_exception);
				}
			}

		private:

			std::atomic<std::uint32_t> m_refCount;

			// Value is either
			// - nullptr          - indicates started, no waiters
			// - this             - indicates value is ready
			// - &this->m_waiters - indicates coroutine not started
			// - other            - pointer to head item in linked-list of waiters.
			//                      values are of type 'cppcoro::shared_task_waiter'.
			//                      indicates that the coroutine has been started.
			std::atomic<void*> m_waiters;

			std::exception_ptr m_exception;

		};

		template<typename T>
		class shared_task_promise : public shared_task_promise_base
		{
		public:

			shared_task_promise() noexcept = default;

			~shared_task_promise()
			{
				if (this->is_ready() && !this->completed_with_unhandled_exception())
				{
					reinterpret_cast<T*>(&m_valueStorage)->~T();
				}
			}

			shared_task<T> get_return_object() noexcept;

			template<
				typename VALUE,
				typename = std::enable_if_t<std::is_convertible_v<VALUE&&, T>>>
			void return_value(VALUE&& value)
				noexcept(std::is_nothrow_constructible_v<T, VALUE&&>)
			{
				new (&m_valueStorage) T(std::forward<VALUE>(value));
			}

			T& result()
			{
				this->rethrow_if_unhandled_exception();
				return *reinterpret_cast<T*>(&m_valueStorage);
			}

		private:

			// Not using std::aligned_storage here due to bug in MSVC 2015 Update 2
			// that means it doesn't work for types with alignof(T) > 8.
			// See MS-Connect bug #2658635.
			alignas(T) char m_valueStorage[sizeof(T)];

		};

		template<>
		class shared_task_promise<void> : public shared_task_promise_base
		{
		public:

			shared_task_promise() noexcept = default;

			shared_task<void> get_return_object() noexcept;

			void return_void() noexcept
			{}

			void result()
			{
				this->rethrow_if_unhandled_exception();
			}

		};

		template<typename T>
		class shared_task_promise<T&> : public shared_task_promise_base
		{
		public:

			shared_task_promise() noexcept = default;

			shared_task<T&> get_return_object() noexcept;

			void return_value(T& value) noexcept
			{
				m_value = std::addressof(value);
			}

			T& result()
			{
				this->rethrow_if_unhandled_exception();
				return *m_value;
			}

		private:

			T* m_value;

		};
	}

	template<typename T = void>
	class [[nodiscard]] shared_task
	{
	public:

		using promise_type = detail::shared_task_promise<T>;

		using value_type = T;

	private:

		struct awaitable_base
		{
			std::coroutine_handle<promise_type> m_coroutine;
			detail::shared_task_waiter m_waiter;

			awaitable_base(std::coroutine_handle<promise_type> coroutine) noexcept
				: m_coroutine(coroutine)
			{}

			bool await_ready() const noexcept
			{
				return !m_coroutine || m_coroutine.promise().is_ready();
			}

			bool await_suspend(std::coroutine_handle<> awaiter) noexcept
			{
				m_waiter.m_continuation = awaiter;
				return m_coroutine.promise().try_await(&m_waiter, m_coroutine);
			}
		};

	public:

		shared_task() noexcept
			: m_coroutine(nullptr)
		{}

		explicit shared_task(std::coroutine_handle<promise_type> coroutine)
			: m_coroutine(coroutine)
		{
			// Don't increment the ref-count here since it has already been
			// initialised to 2 (one for shared_task and one for coroutine)
			// in the shared_task_promise constructor.
		}

		shared_task(shared_task&& other) noexcept
			: m_coroutine(other.m_coroutine)
		{
			other.m_coroutine = nullptr;
		}

		shared_task(const shared_task& other) noexcept
			: m_coroutine(other.m_coroutine)
		{
			if (m_coroutine)
			{
				m_coroutine.promise().add_ref();
			}
		}

		~shared_task()
		{
			destroy();
		}

		shared_task& operator=(shared_task&& other) noexcept
		{
			if (&other != this)
			{
				destroy();

				m_coroutine = other.m_coroutine;
				other.m_coroutine = nullptr;
			}

			return *this;
		}

		shared_task& operator=(const shared_task& other) noexcept
		{
			if (m_coroutine != other.m_coroutine)
			{
				destroy();

				m_coroutine = other.m_coroutine;

				if (m_coroutine)
				{
					m_coroutine.promise().add_ref();
				}
			}

			return *this;
		}

		void swap(shared_task& other) noexcept
		{
			std::swap(m_coroutine, other.m_coroutine);
		}

		/// \brief
		/// Query if the task result is complete.
		///
		/// Awaiting a task that is ready will not block.
		bool is_ready() const noexcept
		{
			return !m_coroutine || m_coroutine.promise().is_ready();
		}

		auto operator co_await() const noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				decltype(auto) await_resume()
				{
					if (!this->m_coroutine)
					{
						throw broken_promise{};
					}

					return this->m_coroutine.promise().result();
				}
			};

			return awaitable{ m_coroutine };
		}

		/// \brief
		/// Returns an awaitable that will await completion of the task without
		/// attempting to retrieve the result.
		auto when_ready() const noexcept
		{
			struct awaitable : awaitable_base
			{
				using awaitable_base::awaitable_base;

				void await_resume() const noexcept {}
			};

			return awaitable{ m_coroutine };
		}

	private:

		template<typename U>
		friend bool operator==(const shared_task<U>&, const shared_task<U>&) noexcept;

		void destroy() noexcept
		{
			if (m_coroutine)
			{
				if (!m_coroutine.promise().try_detach())
				{
					m_coroutine.destroy();
				}
			}
		}

		std::coroutine_handle<promise_type> m_coroutine;

	};

	template<typename T>
	bool operator==(const shared_task<T>& lhs, const shared_task<T>& rhs) noexcept
	{
		return lhs.m_coroutine == rhs.m_coroutine;
	}

	template<typename T>
	bool operator!=(const shared_task<T>& lhs, const shared_task<T>& rhs) noexcept
	{
		return !(lhs == rhs);
	}

	template<typename T>
	void swap(shared_task<T>& a, shared_task<T>& b) noexcept
	{
		a.swap(b);
	}

	namespace detail
	{
		template<typename T>
		shared_task<T> shared_task_promise<T>::get_return_object() noexcept
		{
			return shared_task<T>{
				std::coroutine_handle<shared_task_promise>::from_promise(*this)
			};
		}

		template<typename T>
		shared_task<T&> shared_task_promise<T&>::get_return_object() noexcept
		{
			return shared_task<T&>{
				std::coroutine_handle<shared_task_promise>::from_promise(*this)
			};
		}

		inline shared_task<void> shared_task_promise<void>::get_return_object() noexcept
		{
			return shared_task<void>{
				std::coroutine_handle<shared_task_promise>::from_promise(*this)
			};
		}
	}

	template<typename AWAITABLE>
	auto make_shared_task(AWAITABLE awaitable)
		-> shared_task<detail::remove_rvalue_reference_t<typename awaitable_traits<AWAITABLE>::await_result_t>>
	{
		co_return co_await static_cast<AWAITABLE&&>(awaitable);
	}
}

#endif
