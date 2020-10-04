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
