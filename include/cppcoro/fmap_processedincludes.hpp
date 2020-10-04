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
