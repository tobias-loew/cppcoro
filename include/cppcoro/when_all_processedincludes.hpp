///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_WHEN_ALL_HPP_INCLUDED
#define CPPCORO_WHEN_ALL_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_WHEN_ALL_READY_HPP_INCLUDED
#define CPPCORO_WHEN_ALL_READY_HPP_INCLUDED

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
#ifndef CPPCORO_IS_AWAITABLE_HPP_INCLUDED
#define CPPCORO_IS_AWAITABLE_HPP_INCLUDED

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
	template<typename T, typename = std::void_t<>>
	struct is_awaitable : std::false_type {};

	template<typename T>
	struct is_awaitable<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
		: std::true_type
	{};

	template<typename T>
	constexpr bool is_awaitable_v = is_awaitable<T>::value;
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_WHEN_ALL_READY_AWAITABLE_HPP_INCLUDED
#define CPPCORO_DETAIL_WHEN_ALL_READY_AWAITABLE_HPP_INCLUDED

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_WHEN_ALL_COUNTER_HPP_INCLUDED
#define CPPCORO_DETAIL_WHEN_ALL_COUNTER_HPP_INCLUDED

#include <coroutine>
#include <atomic>
#include <cstdint>

namespace cppcoro
{
	namespace detail
	{
		class when_all_counter
		{
		public:

			when_all_counter(std::size_t count) noexcept
				: m_count(count + 1)
				, m_awaitingCoroutine(nullptr)
			{}

			bool is_ready() const noexcept
			{
				// We consider this complete if we're asking whether it's ready
				// after a coroutine has already been registered.
				return static_cast<bool>(m_awaitingCoroutine);
			}

			bool try_await(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				m_awaitingCoroutine = awaitingCoroutine;
				return m_count.fetch_sub(1, std::memory_order_acq_rel) > 1;
			}

			void notify_awaitable_completed() noexcept
			{
				if (m_count.fetch_sub(1, std::memory_order_acq_rel) == 1)
				{
					m_awaitingCoroutine.resume();
				}
			}

		protected:

			std::atomic<std::size_t> m_count;
			std::coroutine_handle<> m_awaitingCoroutine;

		};
	}
}

#endif

#include <coroutine>
#include <tuple>

namespace cppcoro
{
	namespace detail
	{
		template<typename TASK_CONTAINER>
		class when_all_ready_awaitable;

		template<>
		class when_all_ready_awaitable<std::tuple<>>
		{
		public:

			constexpr when_all_ready_awaitable() noexcept {}
			explicit constexpr when_all_ready_awaitable(std::tuple<>) noexcept {}

			constexpr bool await_ready() const noexcept { return true; }
			void await_suspend(std::coroutine_handle<>) noexcept {}
			std::tuple<> await_resume() const noexcept { return {}; }

		};

		template<typename... TASKS>
		class when_all_ready_awaitable<std::tuple<TASKS...>>
		{
		public:

			explicit when_all_ready_awaitable(TASKS&&... tasks)
				noexcept(std::conjunction_v<std::is_nothrow_move_constructible<TASKS>...>)
				: m_counter(sizeof...(TASKS))
				, m_tasks(std::move(tasks)...)
			{}

			explicit when_all_ready_awaitable(std::tuple<TASKS...>&& tasks)
				noexcept(std::is_nothrow_move_constructible_v<std::tuple<TASKS...>>)
				: m_counter(sizeof...(TASKS))
				, m_tasks(std::move(tasks))
			{}

			when_all_ready_awaitable(when_all_ready_awaitable&& other) noexcept
				: m_counter(sizeof...(TASKS))
				, m_tasks(std::move(other.m_tasks))
			{}

			auto operator co_await() & noexcept
			{
				struct awaiter
				{
					awaiter(when_all_ready_awaitable& awaitable) noexcept
						: m_awaitable(awaitable)
					{}

					bool await_ready() const noexcept
					{
						return m_awaitable.is_ready();
					}

					bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
					{
						return m_awaitable.try_await(awaitingCoroutine);
					}

					std::tuple<TASKS...>& await_resume() noexcept
					{
						return m_awaitable.m_tasks;
					}

				private:

					when_all_ready_awaitable& m_awaitable;

				};

				return awaiter{ *this };
			}

			auto operator co_await() && noexcept
			{
				struct awaiter
				{
					awaiter(when_all_ready_awaitable& awaitable) noexcept
						: m_awaitable(awaitable)
					{}

					bool await_ready() const noexcept
					{
						return m_awaitable.is_ready();
					}

					bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
					{
						return m_awaitable.try_await(awaitingCoroutine);
					}

					std::tuple<TASKS...>&& await_resume() noexcept
					{
						return std::move(m_awaitable.m_tasks);
					}

				private:

					when_all_ready_awaitable& m_awaitable;

				};

				return awaiter{ *this };
			}

		private:

			bool is_ready() const noexcept
			{
				return m_counter.is_ready();
			}

			bool try_await(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				start_tasks(std::make_integer_sequence<std::size_t, sizeof...(TASKS)>{});
				return m_counter.try_await(awaitingCoroutine);
			}

			template<std::size_t... INDICES>
			void start_tasks(std::integer_sequence<std::size_t, INDICES...>) noexcept
			{
				(void)std::initializer_list<int>{
					(std::get<INDICES>(m_tasks).start(m_counter), 0)...
				};
			}

			when_all_counter m_counter;
			std::tuple<TASKS...> m_tasks;

		};

		template<typename TASK_CONTAINER>
		class when_all_ready_awaitable
		{
		public:

			explicit when_all_ready_awaitable(TASK_CONTAINER&& tasks) noexcept
				: m_counter(tasks.size())
				, m_tasks(std::forward<TASK_CONTAINER>(tasks))
			{}

			when_all_ready_awaitable(when_all_ready_awaitable&& other)
				noexcept(std::is_nothrow_move_constructible_v<TASK_CONTAINER>)
				: m_counter(other.m_tasks.size())
				, m_tasks(std::move(other.m_tasks))
			{}

			when_all_ready_awaitable(const when_all_ready_awaitable&) = delete;
			when_all_ready_awaitable& operator=(const when_all_ready_awaitable&) = delete;

			auto operator co_await() & noexcept
			{
				class awaiter
				{
				public:

					awaiter(when_all_ready_awaitable& awaitable)
						: m_awaitable(awaitable)
					{}

					bool await_ready() const noexcept
					{
						return m_awaitable.is_ready();
					}

					bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
					{
						return m_awaitable.try_await(awaitingCoroutine);
					}

					TASK_CONTAINER& await_resume() noexcept
					{
						return m_awaitable.m_tasks;
					}

				private:

					when_all_ready_awaitable& m_awaitable;

				};

				return awaiter{ *this };
			}


			auto operator co_await() && noexcept
			{
				class awaiter
				{
				public:

					awaiter(when_all_ready_awaitable& awaitable)
						: m_awaitable(awaitable)
					{}

					bool await_ready() const noexcept
					{
						return m_awaitable.is_ready();
					}

					bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
					{
						return m_awaitable.try_await(awaitingCoroutine);
					}

					TASK_CONTAINER&& await_resume() noexcept
					{
						return std::move(m_awaitable.m_tasks);
					}

				private:

					when_all_ready_awaitable& m_awaitable;

				};

				return awaiter{ *this };
			}

		private:

			bool is_ready() const noexcept
			{
				return m_counter.is_ready();
			}

			bool try_await(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				for (auto&& task : m_tasks)
				{
					task.start(m_counter);
				}

				return m_counter.try_await(awaitingCoroutine);
			}

			when_all_counter m_counter;
			TASK_CONTAINER m_tasks;

		};
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_WHEN_ALL_TASK_HPP_INCLUDED
#define CPPCORO_DETAIL_WHEN_ALL_TASK_HPP_INCLUDED

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
#ifndef CPPCORO_DETAIL_WHEN_ALL_COUNTER_HPP_INCLUDED
#define CPPCORO_DETAIL_WHEN_ALL_COUNTER_HPP_INCLUDED

#include <coroutine>
#include <atomic>
#include <cstdint>

namespace cppcoro
{
	namespace detail
	{
		class when_all_counter
		{
		public:

			when_all_counter(std::size_t count) noexcept
				: m_count(count + 1)
				, m_awaitingCoroutine(nullptr)
			{}

			bool is_ready() const noexcept
			{
				// We consider this complete if we're asking whether it's ready
				// after a coroutine has already been registered.
				return static_cast<bool>(m_awaitingCoroutine);
			}

			bool try_await(std::coroutine_handle<> awaitingCoroutine) noexcept
			{
				m_awaitingCoroutine = awaitingCoroutine;
				return m_count.fetch_sub(1, std::memory_order_acq_rel) > 1;
			}

			void notify_awaitable_completed() noexcept
			{
				if (m_count.fetch_sub(1, std::memory_order_acq_rel) == 1)
				{
					m_awaitingCoroutine.resume();
				}
			}

		protected:

			std::atomic<std::size_t> m_count;
			std::coroutine_handle<> m_awaitingCoroutine;

		};
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_VOID_VALUE_HPP_INCLUDED
#define CPPCORO_DETAIL_VOID_VALUE_HPP_INCLUDED

namespace cppcoro
{
	namespace detail
	{
		struct void_value {};
	}
}

#endif

#include <coroutine>
#include <cassert>

namespace cppcoro
{
	namespace detail
	{
		template<typename TASK_CONTAINER>
		class when_all_ready_awaitable;

		template<typename RESULT>
		class when_all_task;

		template<typename RESULT>
		class when_all_task_promise final
		{
		public:

			using coroutine_handle_t = std::coroutine_handle<when_all_task_promise<RESULT>>;

			when_all_task_promise() noexcept
			{}

			auto get_return_object() noexcept
			{
				return coroutine_handle_t::from_promise(*this);
			}

			std::suspend_always initial_suspend() noexcept
			{
				return{};
			}

			auto final_suspend() noexcept
			{
				class completion_notifier
				{
				public:

					bool await_ready() const noexcept { return false; }

					void await_suspend(coroutine_handle_t coro) const noexcept
					{
						coro.promise().m_counter->notify_awaitable_completed();
					}

					void await_resume() const noexcept {}

				};

				return completion_notifier{};
			}

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void return_void() noexcept
			{
				// We should have either suspended at co_yield point or
				// an exception was thrown before running off the end of
				// the coroutine.
				assert(false);
			}

#if CPPCORO_COMPILER_MSVC
			// HACK: This is needed to work around a bug in MSVC 2017.7/2017.8.
			// See comment in make_when_all_task below.
			template<typename Awaitable>
			Awaitable&& await_transform(Awaitable&& awaitable)
			{
				return static_cast<Awaitable&&>(awaitable);
			}

			struct get_promise_t {};
			static constexpr get_promise_t get_promise = {};

			auto await_transform(get_promise_t)
			{
				class awaiter
				{
				public:
					awaiter(when_all_task_promise* promise) noexcept : m_promise(promise) {}
					bool await_ready() noexcept {
						return true;
					}
					void await_suspend(std::coroutine_handle<>) noexcept {}
					when_all_task_promise& await_resume() noexcept
					{
						return *m_promise;
					}
				private:
					when_all_task_promise* m_promise;
				};
				return awaiter{ this };
			}
#endif


			auto yield_value(RESULT&& result) noexcept
			{
				m_result = std::addressof(result);
				return final_suspend();
			}

			void start(when_all_counter& counter) noexcept
			{
				m_counter = &counter;
				coroutine_handle_t::from_promise(*this).resume();
			}

			RESULT& result() &
			{
				rethrow_if_exception();
				return *m_result;
			}

			RESULT&& result() &&
			{
				rethrow_if_exception();
				return std::forward<RESULT>(*m_result);
			}

		private:

			void rethrow_if_exception()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}
			}

			when_all_counter* m_counter;
			std::exception_ptr m_exception;
			std::add_pointer_t<RESULT> m_result;

		};

		template<>
		class when_all_task_promise<void> final
		{
		public:

			using coroutine_handle_t = std::coroutine_handle<when_all_task_promise<void>>;

			when_all_task_promise() noexcept
			{}

			auto get_return_object() noexcept
			{
				return coroutine_handle_t::from_promise(*this);
			}

			std::suspend_always initial_suspend() noexcept
			{
				return{};
			}

			auto final_suspend() noexcept
			{
				class completion_notifier
				{
				public:

					bool await_ready() const noexcept { return false; }

					void await_suspend(coroutine_handle_t coro) const noexcept
					{
						coro.promise().m_counter->notify_awaitable_completed();
					}

					void await_resume() const noexcept {}

				};

				return completion_notifier{};
			}

			void unhandled_exception() noexcept
			{
				m_exception = std::current_exception();
			}

			void return_void() noexcept
			{
			}

			void start(when_all_counter& counter) noexcept
			{
				m_counter = &counter;
				coroutine_handle_t::from_promise(*this).resume();
			}

			void result()
			{
				if (m_exception)
				{
					std::rethrow_exception(m_exception);
				}
			}

		private:

			when_all_counter* m_counter;
			std::exception_ptr m_exception;

		};

		template<typename RESULT>
		class when_all_task final
		{
		public:

			using promise_type = when_all_task_promise<RESULT>;

			using coroutine_handle_t = typename promise_type::coroutine_handle_t;

			when_all_task(coroutine_handle_t coroutine) noexcept
				: m_coroutine(coroutine)
			{}

			when_all_task(when_all_task&& other) noexcept
				: m_coroutine(std::exchange(other.m_coroutine, coroutine_handle_t{}))
			{}

			~when_all_task()
			{
				if (m_coroutine) m_coroutine.destroy();
			}

			when_all_task(const when_all_task&) = delete;
			when_all_task& operator=(const when_all_task&) = delete;

			decltype(auto) result() &
			{
				return m_coroutine.promise().result();
			}

			decltype(auto) result() &&
			{
				return std::move(m_coroutine.promise()).result();
			}

			decltype(auto) non_void_result() &
			{
				if constexpr (std::is_void_v<decltype(this->result())>)
				{
					this->result();
					return void_value{};
				}
				else
				{
					return this->result();
				}
			}

			decltype(auto) non_void_result() &&
			{
				if constexpr (std::is_void_v<decltype(this->result())>)
				{
					std::move(*this).result();
					return void_value{};
				}
				else
				{
					return std::move(*this).result();
				}
			}

		private:

			template<typename TASK_CONTAINER>
			friend class when_all_ready_awaitable;

			void start(when_all_counter& counter) noexcept
			{
				m_coroutine.promise().start(counter);
			}

			coroutine_handle_t m_coroutine;

		};

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<!std::is_void_v<RESULT>, int> = 0>
		when_all_task<RESULT> make_when_all_task(AWAITABLE awaitable)
		{
#if CPPCORO_COMPILER_MSVC
			// HACK: Workaround another bug in MSVC where the expression 'co_yield co_await x' seems
			// to completely ignore the co_yield an never calls promise.yield_value().
			// The coroutine seems to be resuming the 'co_await' after the 'co_yield'
			// rather than before the 'co_yield'.
			// This bug is present in VS 2017.7 and VS 2017.8.
			auto& promise = co_await when_all_task_promise<RESULT>::get_promise;
			co_await promise.yield_value(co_await std::forward<AWAITABLE>(awaitable));
#else
			co_yield co_await static_cast<AWAITABLE&&>(awaitable);
#endif
		}

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&&>::await_result_t,
			std::enable_if_t<std::is_void_v<RESULT>, int> = 0>
		when_all_task<void> make_when_all_task(AWAITABLE awaitable)
		{
			co_await static_cast<AWAITABLE&&>(awaitable);
		}

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&>::await_result_t,
			std::enable_if_t<!std::is_void_v<RESULT>, int> = 0>
		when_all_task<RESULT> make_when_all_task(std::reference_wrapper<AWAITABLE> awaitable)
		{
#if CPPCORO_COMPILER_MSVC
			// HACK: Workaround another bug in MSVC where the expression 'co_yield co_await x' seems
			// to completely ignore the co_yield and never calls promise.yield_value().
			// The coroutine seems to be resuming the 'co_await' after the 'co_yield'
			// rather than before the 'co_yield'.
			// This bug is present in VS 2017.7 and VS 2017.8.
			auto& promise = co_await when_all_task_promise<RESULT>::get_promise;
			co_await promise.yield_value(co_await awaitable.get());
#else
			co_yield co_await awaitable.get();
#endif
		}

		template<
			typename AWAITABLE,
			typename RESULT = typename cppcoro::awaitable_traits<AWAITABLE&>::await_result_t,
			std::enable_if_t<std::is_void_v<RESULT>, int> = 0>
		when_all_task<void> make_when_all_task(std::reference_wrapper<AWAITABLE> awaitable)
		{
			co_await awaitable.get();
		}
	}
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_UNWRAP_REFERENCE_HPP_INCLUDED
#define CPPCORO_DETAIL_UNWRAP_REFERENCE_HPP_INCLUDED

#include <functional>

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct unwrap_reference
		{
			using type = T;
		};

		template<typename T>
		struct unwrap_reference<std::reference_wrapper<T>>
		{
			using type = T;
		};

		template<typename T>
		using unwrap_reference_t = typename unwrap_reference<T>::type;
	}
}

#endif

#include <tuple>
#include <utility>
#include <vector>
#include <type_traits>

namespace cppcoro
{
	template<
		typename... AWAITABLES,
		std::enable_if_t<std::conjunction_v<
			is_awaitable<detail::unwrap_reference_t<std::remove_reference_t<AWAITABLES>>>...>, int> = 0>
	[[nodiscard]]
	CPPCORO_FORCE_INLINE auto when_all_ready(AWAITABLES&&... awaitables)
	{
		return detail::when_all_ready_awaitable<std::tuple<detail::when_all_task<
			typename awaitable_traits<detail::unwrap_reference_t<std::remove_reference_t<AWAITABLES>>>::await_result_t>...>>(
				std::make_tuple(detail::make_when_all_task(std::forward<AWAITABLES>(awaitables))...));
	}

	// TODO: Generalise this from vector<AWAITABLE> to arbitrary sequence of awaitable.

	template<
		typename AWAITABLE,
		typename RESULT = typename awaitable_traits<detail::unwrap_reference_t<AWAITABLE>>::await_result_t>
	[[nodiscard]] auto when_all_ready(std::vector<AWAITABLE> awaitables)
	{
		std::vector<detail::when_all_task<RESULT>> tasks;

		tasks.reserve(awaitables.size());

		for (auto& awaitable : awaitables)
		{
			tasks.emplace_back(detail::make_when_all_task(std::move(awaitable)));
		}

		return detail::when_all_ready_awaitable<std::vector<detail::when_all_task<RESULT>>>(
			std::move(tasks));
	}
}

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
#ifndef CPPCORO_IS_AWAITABLE_HPP_INCLUDED
#define CPPCORO_IS_AWAITABLE_HPP_INCLUDED

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
	template<typename T, typename = std::void_t<>>
	struct is_awaitable : std::false_type {};

	template<typename T>
	struct is_awaitable<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
		: std::true_type
	{};

	template<typename T>
	constexpr bool is_awaitable_v = is_awaitable<T>::value;
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_FMAP_HPP_INCLUDED
#define CPPCORO_FMAP_HPP_INCLUDED

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
#ifndef CPPCORO_IS_AWAITABLE_HPP_INCLUDED
#define CPPCORO_IS_AWAITABLE_HPP_INCLUDED

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
	template<typename T, typename = std::void_t<>>
	struct is_awaitable : std::false_type {};

	template<typename T>
	struct is_awaitable<T, std::void_t<decltype(cppcoro::detail::get_awaiter(std::declval<T>()))>>
		: std::true_type
	{};

	template<typename T>
	constexpr bool is_awaitable_v = is_awaitable<T>::value;
}

#endif

#include <utility>
#include <type_traits>
#include <functional>

namespace cppcoro
{
	namespace detail
	{
		template<typename FUNC, typename AWAITABLE>
		class fmap_awaiter
		{
			using awaiter_t = typename awaitable_traits<AWAITABLE&&>::awaiter_t;

		public:

			fmap_awaiter(FUNC&& func, AWAITABLE&& awaitable)
				noexcept(
					std::is_nothrow_move_constructible_v<awaiter_t> &&
					noexcept(detail::get_awaiter(static_cast<AWAITABLE&&>(awaitable))))
				: m_func(static_cast<FUNC&&>(func))
				, m_awaiter(detail::get_awaiter(static_cast<AWAITABLE&&>(awaitable)))
			{}

			decltype(auto) await_ready()
				noexcept(noexcept(static_cast<awaiter_t&&>(m_awaiter).await_ready()))
			{
				return static_cast<awaiter_t&&>(m_awaiter).await_ready();
			}

			template<typename PROMISE>
			decltype(auto) await_suspend(std::coroutine_handle<PROMISE> coro)
				noexcept(noexcept(static_cast<awaiter_t&&>(m_awaiter).await_suspend(std::move(coro))))
			{
				return static_cast<awaiter_t&&>(m_awaiter).await_suspend(std::move(coro));
			}

			template<
				typename AWAIT_RESULT = decltype(std::declval<awaiter_t>().await_resume()),
				std::enable_if_t<std::is_void_v<AWAIT_RESULT>, int> = 0>
			decltype(auto) await_resume()
				noexcept(noexcept(std::invoke(static_cast<FUNC&&>(m_func))))
			{
				static_cast<awaiter_t&&>(m_awaiter).await_resume();
				return std::invoke(static_cast<FUNC&&>(m_func));
			}

			template<
				typename AWAIT_RESULT = decltype(std::declval<awaiter_t>().await_resume()),
				std::enable_if_t<!std::is_void_v<AWAIT_RESULT>, int> = 0>
			decltype(auto) await_resume()
				noexcept(noexcept(std::invoke(static_cast<FUNC&&>(m_func), static_cast<awaiter_t&&>(m_awaiter).await_resume())))
			{
				return std::invoke(
					static_cast<FUNC&&>(m_func),
					static_cast<awaiter_t&&>(m_awaiter).await_resume());
			}

		private:

			FUNC&& m_func;
			awaiter_t m_awaiter;

		};

		template<typename FUNC, typename AWAITABLE>
		class fmap_awaitable
		{
			static_assert(!std::is_lvalue_reference_v<FUNC>);
			static_assert(!std::is_lvalue_reference_v<AWAITABLE>);
		public:

			template<
				typename FUNC_ARG,
				typename AWAITABLE_ARG,
				std::enable_if_t<
					std::is_constructible_v<FUNC, FUNC_ARG&&> &&
					std::is_constructible_v<AWAITABLE, AWAITABLE_ARG&&>, int> = 0>
			explicit fmap_awaitable(FUNC_ARG&& func, AWAITABLE_ARG&& awaitable)
				noexcept(
					std::is_nothrow_constructible_v<FUNC, FUNC_ARG&&> &&
					std::is_nothrow_constructible_v<AWAITABLE, AWAITABLE_ARG&&>)
				: m_func(static_cast<FUNC_ARG&&>(func))
				, m_awaitable(static_cast<AWAITABLE_ARG&&>(awaitable))
			{}

			auto operator co_await() const &
			{
				return fmap_awaiter<const FUNC&, const AWAITABLE&>(m_func, m_awaitable);
			}

			auto operator co_await() &
			{
				return fmap_awaiter<FUNC&, AWAITABLE&>(m_func, m_awaitable);
			}

			auto operator co_await() &&
			{
				return fmap_awaiter<FUNC&&, AWAITABLE&&>(
					static_cast<FUNC&&>(m_func),
					static_cast<AWAITABLE&&>(m_awaitable));
			}

		private:

			FUNC m_func;
			AWAITABLE m_awaitable;

		};
	}

	template<typename FUNC>
	struct fmap_transform
	{
		explicit fmap_transform(FUNC&& f)
			noexcept(std::is_nothrow_move_constructible_v<FUNC>)
			: func(std::forward<FUNC>(f))
		{}

		FUNC func;
	};

	template<
		typename FUNC,
		typename AWAITABLE,
		std::enable_if_t<cppcoro::is_awaitable_v<AWAITABLE>, int> = 0>
	auto fmap(FUNC&& func, AWAITABLE&& awaitable)
	{
		return detail::fmap_awaitable<
			std::remove_cv_t<std::remove_reference_t<FUNC>>,
			std::remove_cv_t<std::remove_reference_t<AWAITABLE>>>(
			std::forward<FUNC>(func),
			std::forward<AWAITABLE>(awaitable));
	}

	template<typename FUNC>
	auto fmap(FUNC&& func)
	{
		return fmap_transform<FUNC>{ std::forward<FUNC>(func) };
	}

	template<typename T, typename FUNC>
	decltype(auto) operator|(T&& value, fmap_transform<FUNC>&& transform)
	{
		// Use ADL for finding fmap() overload.
		return fmap(std::forward<FUNC>(transform.func), std::forward<T>(value));
	}

	template<typename T, typename FUNC>
	decltype(auto) operator|(T&& value, const fmap_transform<FUNC>& transform)
	{
		// Use ADL for finding fmap() overload.
		return fmap(transform.func, std::forward<T>(value));
	}

	template<typename T, typename FUNC>
	decltype(auto) operator|(T&& value, fmap_transform<FUNC>& transform)
	{
		// Use ADL for finding fmap() overload.
		return fmap(transform.func, std::forward<T>(value));
	}
}

#endif

///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_UNWRAP_REFERENCE_HPP_INCLUDED
#define CPPCORO_DETAIL_UNWRAP_REFERENCE_HPP_INCLUDED

#include <functional>

namespace cppcoro
{
	namespace detail
	{
		template<typename T>
		struct unwrap_reference
		{
			using type = T;
		};

		template<typename T>
		struct unwrap_reference<std::reference_wrapper<T>>
		{
			using type = T;
		};

		template<typename T>
		using unwrap_reference_t = typename unwrap_reference<T>::type;
	}
}

#endif

#include <tuple>
#include <functional>
#include <utility>
#include <vector>
#include <type_traits>
#include <cassert>

namespace cppcoro
{
	//////////
	// Variadic when_all()

	template<
		typename... AWAITABLES,
		std::enable_if_t<
			std::conjunction_v<is_awaitable<detail::unwrap_reference_t<std::remove_reference_t<AWAITABLES>>>...>,
			int> = 0>
	[[nodiscard]] auto when_all(AWAITABLES&&... awaitables)
	{
		return fmap([](auto&& taskTuple)
		{
			return std::apply([](auto&&... tasks) {
				return std::make_tuple(static_cast<decltype(tasks)>(tasks).non_void_result()...);
			}, static_cast<decltype(taskTuple)>(taskTuple));
		}, when_all_ready(std::forward<AWAITABLES>(awaitables)...));
	}

	//////////
	// when_all() with vector of awaitable

	template<
		typename AWAITABLE,
		typename RESULT = typename awaitable_traits<detail::unwrap_reference_t<AWAITABLE>>::await_result_t,
		std::enable_if_t<std::is_void_v<RESULT>, int> = 0>
	[[nodiscard]]
	auto when_all(std::vector<AWAITABLE> awaitables)
	{
		return fmap([](auto&& taskVector) {
			for (auto& task : taskVector)
			{
				task.result();
			}
		}, when_all_ready(std::move(awaitables)));
	}

	template<
		typename AWAITABLE,
		typename RESULT = typename awaitable_traits<detail::unwrap_reference_t<AWAITABLE>>::await_result_t,
		std::enable_if_t<!std::is_void_v<RESULT>, int> = 0>
	[[nodiscard]]
	auto when_all(std::vector<AWAITABLE> awaitables)
	{
		using result_t = std::conditional_t<
			std::is_lvalue_reference_v<RESULT>,
			std::reference_wrapper<std::remove_reference_t<RESULT>>,
			std::remove_reference_t<RESULT>>;

		return fmap([](auto&& taskVector) {
			std::vector<result_t> results;
			results.reserve(taskVector.size());
			for (auto& task : taskVector)
			{
				if constexpr (std::is_rvalue_reference_v<decltype(taskVector)>)
				{
					results.emplace_back(std::move(task).result());
				}
				else
				{
					results.emplace_back(task.result());
				}
			}
			return results;
		}, when_all_ready(std::move(awaitables)));
	}
}

#endif
