///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_SEQUENCE_BARRIER_HPP_INCLUDED
#define CPPCORO_SEQUENCE_BARRIER_HPP_INCLUDED

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
#ifndef CPPCORO_SEQUENCE_TRAITS_HPP_INCLUDED
#define CPPCORO_SEQUENCE_TRAITS_HPP_INCLUDED

#include <type_traits>

namespace cppcoro
{
	template<typename SEQUENCE>
	struct sequence_traits
	{
		using value_type = SEQUENCE;
		using difference_type = std::make_signed_t<SEQUENCE>;
		using size_type = std::make_unsigned_t<SEQUENCE>;

		static constexpr value_type initial_sequence = static_cast<value_type>(-1);

		static constexpr difference_type difference(value_type a, value_type b)
		{
			return static_cast<difference_type>(a - b);
		}

		static constexpr bool precedes(value_type a, value_type b)
		{
			return difference(a, b) < 0;
		}
	};
}

#endif
///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////
#ifndef CPPCORO_DETAIL_MANUAL_LIFETIME_HPP_INCLUDED
#define CPPCORO_DETAIL_MANUAL_LIFETIME_HPP_INCLUDED

#include <type_traits>
#include <memory>

namespace cppcoro::detail
{
	template<typename T>
	struct manual_lifetime
	{
	public:
		manual_lifetime() noexcept {}
		~manual_lifetime() noexcept {}

		manual_lifetime(const manual_lifetime&) = delete;
		manual_lifetime(manual_lifetime&&) = delete;
		manual_lifetime& operator=(const manual_lifetime&) = delete;
		manual_lifetime& operator=(manual_lifetime&&) = delete;

		template<typename... Args>
		std::enable_if_t<std::is_constructible_v<T, Args&&...>> construct(Args&&... args)
			noexcept(std::is_nothrow_constructible_v<T, Args&&...>)
		{
			::new (static_cast<void*>(std::addressof(m_value))) T(static_cast<Args&&>(args)...);
		}

		void destruct() noexcept(std::is_nothrow_destructible_v<T>)
		{
			m_value.~T();
		}

		std::add_pointer_t<T> operator->() noexcept { return std::addressof(**this); }
		std::add_pointer_t<const T> operator->() const noexcept { return std::addressof(**this); }

		T& operator*() & noexcept { return m_value; }
		const T& operator*() const & noexcept { return m_value; }
		T&& operator*() && noexcept { return static_cast<T&&>(m_value); }
		const T&& operator*() const && noexcept { return static_cast<const T&&>(m_value); }

	private:
		union {
			T m_value;
		};
	};

	template<typename T>
	struct manual_lifetime<T&>
	{
	public:
		manual_lifetime() noexcept {}
		~manual_lifetime() noexcept {}

		manual_lifetime(const manual_lifetime&) = delete;
		manual_lifetime(manual_lifetime&&) = delete;
		manual_lifetime& operator=(const manual_lifetime&) = delete;
		manual_lifetime& operator=(manual_lifetime&&) = delete;

		void construct(T& value) noexcept
		{
			m_value = std::addressof(value);
		}

		void destruct() noexcept {}

		T* operator->() noexcept { return m_value; }
		const T* operator->() const noexcept { return m_value; }

		T& operator*() noexcept { return *m_value; }
		const T& operator*() const noexcept { return *m_value; }

	private:
		T* m_value;
	};

	template<typename T>
	struct manual_lifetime<T&&>
	{
	public:
		manual_lifetime() noexcept {}
		~manual_lifetime() noexcept {}

		manual_lifetime(const manual_lifetime&) = delete;
		manual_lifetime(manual_lifetime&&) = delete;
		manual_lifetime& operator=(const manual_lifetime&) = delete;
		manual_lifetime& operator=(manual_lifetime&&) = delete;

		void construct(T&& value) noexcept
		{
			m_value = std::addressof(value);
		}

		void destruct() noexcept {}

		T* operator->() noexcept { return m_value; }
		const T* operator->() const noexcept { return m_value; }

		T& operator*() & noexcept { return *m_value; }
		const T& operator*() const & noexcept { return *m_value; }
		T&& operator*() && noexcept { return static_cast<T&&>(*m_value); }
		const T&& operator*() const && noexcept { return static_cast<const T&&>(*m_value); }

	private:
		T* m_value;
	};

	template<>
	struct manual_lifetime<void>
	{
		void construct() noexcept {}
		void destruct() noexcept {}
		void operator*() const noexcept {}
	};
}

#endif

#include <atomic>
#include <cassert>
#include <cstdint>
#include <limits>
#include <optional>
#include <coroutine>

namespace cppcoro
{
	template<typename SEQUENCE, typename TRAITS>
	class sequence_barrier_wait_operation_base;

	template<typename SEQUENCE, typename TRAITS, typename SCHEDULER>
	class sequence_barrier_wait_operation;

	/// A sequence barrier is a synchronisation primitive that allows a single-producer
	/// and multiple-consumers to coordinate with respect to a monotonically increasing
	/// sequence number.
	///
	/// A single producer advances the sequence number by publishing new sequence numbers in a
	/// monotonically increasing order. One or more consumers can query the last-published
	/// sequence number and can wait until a particular sequence number has been published.
	///
	/// A sequence barrier can be used to represent a cursor into a thread-safe producer/consumer
	/// ring-buffer.
	///
	/// See the LMAX Disruptor pattern for more background:
	/// https://lmax-exchange.github.io/disruptor/files/Disruptor-1.0.pdf
	template<
		typename SEQUENCE = std::size_t,
		typename TRAITS = sequence_traits<SEQUENCE>>
	class sequence_barrier
	{
		static_assert(
			std::is_integral_v<SEQUENCE>,
			"sequence_barrier requires an integral sequence type");

		using awaiter_t = sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>;

	public:

		/// Construct a sequence barrier with the specified initial sequence number
		/// as the initial value 'last_published()'.
		sequence_barrier(SEQUENCE initialSequence = TRAITS::initial_sequence) noexcept
			: m_lastPublished(initialSequence)
			, m_awaiters(nullptr)
		{}

		~sequence_barrier()
		{
			// Shouldn't be destructing a sequence barrier if there are still waiters.
			assert(m_awaiters.load(std::memory_order_relaxed) == nullptr);
		}

		/// Query the sequence number that was most recently published by the producer.
		///
		/// You can assume that all sequence numbers prior to the returned sequence number
		/// have also been published. This means you can safely access all elements with
		/// sequence numbers up to and including the returned sequence number without any
		/// further synchronisation.
		SEQUENCE last_published() const noexcept
		{
			return m_lastPublished.load(std::memory_order_acquire);
		}

		/// Wait until a particular sequence number has been published.
		///
		/// If the specified sequence number is not yet published then the awaiting coroutine
		/// will be suspended and later resumed inside the call to publish() that publishes
		/// the specified sequence number.
		///
		/// \param targetSequence
		/// The sequence number to wait for.
		///
		/// \return
		/// An awaitable that when co_await'ed will suspend the awaiting coroutine until
		/// the specified target sequence number has been published.
		/// The result of the co_await expression will be the last-known published sequence
		/// number. This is guaranteed not to precede \p targetSequence but may be a sequence
		/// number after \p targetSequence, which indicates that more elements have been
		/// published than you were waiting for.
		template<typename SCHEDULER>
		[[nodiscard]]
		sequence_barrier_wait_operation<SEQUENCE, TRAITS, SCHEDULER> wait_until_published(
			SEQUENCE targetSequence,
			SCHEDULER& scheduler) const noexcept;

		/// Publish the specified sequence number to consumers.
		///
		/// This publishes all sequence numbers up to and including the specified sequence
		/// number. This will resume any coroutine that was suspended waiting for a sequence
		/// number that was published by this operation.
		///
		/// \param sequence
		/// The sequence number to publish. This number must not precede the current
		/// last_published() value. ie. the published sequence numbers must be monotonically
		/// increasing.
		void publish(SEQUENCE sequence) noexcept;

	private:

		friend class sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>;

		void add_awaiter(awaiter_t* awaiter) const noexcept;

#if CPPCORO_COMPILER_MSVC
# pragma warning(push)
# pragma warning(disable : 4324) // C4324: structure was padded due to alignment specifier
#endif

		// First cache-line is written to by the producer only
		alignas(CPPCORO_CPU_CACHE_LINE)
		std::atomic<SEQUENCE> m_lastPublished;

		// Second cache-line is written to by both the producer and consumers
		alignas(CPPCORO_CPU_CACHE_LINE)
		mutable std::atomic<awaiter_t*> m_awaiters;

#if CPPCORO_COMPILER_MSVC
# pragma warning(pop)
#endif

	};

	template<typename SEQUENCE, typename TRAITS>
	class sequence_barrier_wait_operation_base
	{
	public:

		explicit sequence_barrier_wait_operation_base(
			const sequence_barrier<SEQUENCE, TRAITS>& barrier,
			SEQUENCE targetSequence) noexcept
			: m_barrier(barrier)
			, m_targetSequence(targetSequence)
			, m_lastKnownPublished(barrier.last_published())
			, m_readyToResume(false)
		{}

		sequence_barrier_wait_operation_base(
			const sequence_barrier_wait_operation_base& other) noexcept
			: m_barrier(other.m_barrier)
			, m_targetSequence(other.m_targetSequence)
			, m_lastKnownPublished(other.m_lastKnownPublished)
			, m_readyToResume(false)
		{}

		bool await_ready() const noexcept
		{
			return !TRAITS::precedes(m_lastKnownPublished, m_targetSequence);
		}

		bool await_suspend(std::coroutine_handle<> awaitingCoroutine) noexcept
		{
			m_awaitingCoroutine = awaitingCoroutine;
			m_barrier.add_awaiter(this);
			return !m_readyToResume.exchange(true, std::memory_order_acquire);
		}

		SEQUENCE await_resume() noexcept
		{
			return m_lastKnownPublished;
		}

	protected:

		friend class sequence_barrier<SEQUENCE, TRAITS>;

		void resume() noexcept
		{
			// This synchronises with the exchange(true, std::memory_order_acquire) in await_suspend().
			if (m_readyToResume.exchange(true, std::memory_order_release))
			{
				resume_impl();
			}
		}

		virtual void resume_impl() noexcept = 0;

		const sequence_barrier<SEQUENCE, TRAITS>& m_barrier;
		const SEQUENCE m_targetSequence;
		SEQUENCE m_lastKnownPublished;
		sequence_barrier_wait_operation_base* m_next;
		std::coroutine_handle<> m_awaitingCoroutine;
		std::atomic<bool> m_readyToResume;

	};

	template<typename SEQUENCE, typename TRAITS, typename SCHEDULER>
	class sequence_barrier_wait_operation : public sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>
	{
		using schedule_operation = decltype(std::declval<SCHEDULER&>().schedule());

	public:
		sequence_barrier_wait_operation(
			const sequence_barrier<SEQUENCE, TRAITS>& barrier,
			SEQUENCE targetSequence,
			SCHEDULER& scheduler) noexcept
			: sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>(barrier, targetSequence)
			, m_scheduler(scheduler)
		{}

		sequence_barrier_wait_operation(
			const sequence_barrier_wait_operation& other) noexcept
			: sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>(other)
			, m_scheduler(other.m_scheduler)
		{}

		~sequence_barrier_wait_operation()
		{
			if (m_isScheduleAwaiterCreated)
			{
				m_scheduleAwaiter.destruct();
			}
			if (m_isScheduleOperationCreated)
			{
				m_scheduleOperation.destruct();
			}
		}

		decltype(auto) await_resume() noexcept(noexcept(m_scheduleAwaiter->await_resume()))
		{
			if (m_isScheduleAwaiterCreated)
			{
				m_scheduleAwaiter->await_resume();
			}

			return sequence_barrier_wait_operation_base<SEQUENCE, TRAITS>::await_resume();
		}

	private:

		void resume_impl() noexcept override
		{
			try
			{
				m_scheduleOperation.construct(m_scheduler.schedule());
				m_isScheduleOperationCreated = true;

				m_scheduleAwaiter.construct(detail::get_awaiter(
					static_cast<schedule_operation&&>(*m_scheduleOperation)));
				m_isScheduleAwaiterCreated = true;

				if (!m_scheduleAwaiter->await_ready())
				{
					using await_suspend_result_t = decltype(m_scheduleAwaiter->await_suspend(this->m_awaitingCoroutine));
					if constexpr (std::is_void_v<await_suspend_result_t>)
					{
						m_scheduleAwaiter->await_suspend(this->m_awaitingCoroutine);
						return;
					}
					else if constexpr (std::is_same_v<await_suspend_result_t, bool>)
					{
						if (m_scheduleAwaiter->await_suspend(this->m_awaitingCoroutine))
						{
							return;
						}
					}
					else
					{
						// Assume it returns a coroutine_handle.
						m_scheduleAwaiter->await_suspend(this->m_awaitingCoroutine).resume();
						return;
					}
				}
			}
			catch (...)
			{
				// Ignore failure to reschedule and resume inline?
				// Should we catch the exception and rethrow from await_resume()?
				// Or should we require that 'co_await scheduler.schedule()' is noexcept?
			}

			// Resume outside the catch-block.
			this->m_awaitingCoroutine.resume();
		}

		SCHEDULER& m_scheduler;
		// Can't use std::optional<T> here since T could be a reference.
		detail::manual_lifetime<schedule_operation> m_scheduleOperation;
		detail::manual_lifetime<typename awaitable_traits<schedule_operation>::awaiter_t> m_scheduleAwaiter;
		bool m_isScheduleOperationCreated = false;
		bool m_isScheduleAwaiterCreated = false;
	};

	template<typename SEQUENCE, typename TRAITS>
	template<typename SCHEDULER>
	[[nodiscard]]
	sequence_barrier_wait_operation<SEQUENCE, TRAITS, SCHEDULER> sequence_barrier<SEQUENCE, TRAITS>::wait_until_published(
		SEQUENCE targetSequence,
		SCHEDULER& scheduler) const noexcept
	{
		return sequence_barrier_wait_operation<SEQUENCE, TRAITS, SCHEDULER>(*this, targetSequence, scheduler);
	}

	template<typename SEQUENCE, typename TRAITS>
	void sequence_barrier<SEQUENCE, TRAITS>::publish(SEQUENCE sequence) noexcept
	{
		m_lastPublished.store(sequence, std::memory_order_seq_cst);

		// Cheaper check to see if there are any awaiting coroutines.
		auto* awaiters = m_awaiters.load(std::memory_order_seq_cst);
		if (awaiters == nullptr)
		{
			return;
		}

		// Acquire the list of awaiters.
		// Note we may be racing with add_awaiter() which could also acquire the list of waiters
		// so we need to check again whether we won the race and acquired the list.
		awaiters = m_awaiters.exchange(nullptr, std::memory_order_acquire);
		if (awaiters == nullptr)
		{
			return;
		}

		// Check the list of awaiters for ones that are now satisfied by the sequence number
		// we just published. Awaiters are added to either the 'awaitersToResume' list or to
		// the 'awaitersToRequeue' list.
		awaiter_t* awaitersToResume;
		awaiter_t** awaitersToResumeTail = &awaitersToResume;

		awaiter_t* awaitersToRequeue;
		awaiter_t** awaitersToRequeueTail = &awaitersToRequeue;

		do
		{
			if (TRAITS::precedes(sequence, awaiters->m_targetSequence))
			{
				// Target sequence not reached. Append to 'requeue' list.
				*awaitersToRequeueTail = awaiters;
				awaitersToRequeueTail = &awaiters->m_next;
			}
			else
			{
				// Target sequence reached. Append to 'resume' list.
				*awaitersToResumeTail = awaiters;
				awaitersToResumeTail = &awaiters->m_next;
			}
			awaiters = awaiters->m_next;
		} while (awaiters != nullptr);

		// Null-terminate the two lists.
		*awaitersToRequeueTail = nullptr;
		*awaitersToResumeTail = nullptr;

		if (awaitersToRequeue != nullptr)
		{
			awaiter_t* oldHead = nullptr;
			while (!m_awaiters.compare_exchange_weak(
				oldHead,
				awaitersToRequeue,
				std::memory_order_release,
				std::memory_order_relaxed))
			{
				*awaitersToRequeueTail = oldHead;
			}
		}

		while (awaitersToResume != nullptr)
		{
			auto* next = awaitersToResume->m_next;
			awaitersToResume->m_lastKnownPublished = sequence;
			awaitersToResume->resume();
			awaitersToResume = next;
		}
	}

	template<typename SEQUENCE, typename TRAITS>
	void sequence_barrier<SEQUENCE, TRAITS>::add_awaiter(awaiter_t* awaiter) const noexcept
	{
		SEQUENCE targetSequence = awaiter->m_targetSequence;
		awaiter_t* awaitersToRequeue = awaiter;
		awaiter_t** awaitersToRequeueTail = &awaiter->m_next;

		SEQUENCE lastKnownPublished;
		awaiter_t* awaitersToResume;
		awaiter_t** awaitersToResumeTail = &awaitersToResume;

		do
		{
			// Enqueue the awaiter(s)
			{
				auto* oldHead = m_awaiters.load(std::memory_order_relaxed);
				do
				{
					*awaitersToRequeueTail = oldHead;
				} while (!m_awaiters.compare_exchange_weak(
					oldHead,
					awaitersToRequeue,
					std::memory_order_seq_cst,
					std::memory_order_relaxed));
			}

			// Check that the sequence we were waiting for wasn't published while
			// we were enqueueing the waiter.
			// This needs to be seq_cst memory order to ensure that in the case that the producer
			// publishes a new sequence number concurrently with this call that we either see
			// their write to m_lastPublished after enqueueing our awaiter, or they see our
			// write to m_awaiters after their write to m_lastPublished.
			lastKnownPublished = m_lastPublished.load(std::memory_order_seq_cst);
			if (TRAITS::precedes(lastKnownPublished, targetSequence))
			{
				// None of the the awaiters we enqueued have been satisfied yet.
				break;
			}

			// Reset the requeue list to empty
			awaitersToRequeueTail = &awaitersToRequeue;

			// At least one of the awaiters we just enqueued is now satisfied by a concurrently
			// published sequence number. The producer thread may not have seen our write to m_awaiters
			// so we need to try to re-acquire the list of awaiters to ensure that the waiters that
			// are now satisfied are woken up.
			auto* awaiters = m_awaiters.exchange(nullptr, std::memory_order_acquire);

			auto minDiff = std::numeric_limits<typename TRAITS::difference_type>::max();

			while (awaiters != nullptr)
			{
				const auto diff = TRAITS::difference(awaiters->m_targetSequence, lastKnownPublished);
				if (diff > 0)
				{
					*awaitersToRequeueTail = awaiters;
					awaitersToRequeueTail = &awaiters->m_next;
					minDiff = diff < minDiff ? diff : minDiff;
				}
				else
				{
					*awaitersToResumeTail = awaiters;
					awaitersToResumeTail = &awaiters->m_next;
				}

				awaiters = awaiters->m_next;
			}

			// Null-terminate the list of awaiters to requeue.
			*awaitersToRequeueTail = nullptr;

			// Calculate the earliest target sequence required by any of the awaiters to requeue.
			targetSequence = static_cast<SEQUENCE>(lastKnownPublished + minDiff);

		} while (awaitersToRequeue != nullptr);

		// Null-terminate the list of awaiters to resume
		*awaitersToResumeTail = nullptr;

		// Resume the awaiters that are ready
		while (awaitersToResume != nullptr)
		{
			auto* next = awaitersToResume->m_next;
			awaitersToResume->m_lastKnownPublished = lastKnownPublished;
			awaitersToResume->resume();
			awaitersToResume = next;
		}
	}
}

#endif
