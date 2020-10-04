///////////////////////////////////////////////////////////////////////////////
// Copyright (c) Lewis Baker
// Licenced under MIT license. See LICENSE.txt for details.
///////////////////////////////////////////////////////////////////////////////

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

#include "cancellation_state.hpp"

#include <utility>
#include <cassert>

cppcoro::cancellation_token::cancellation_token() noexcept
	: m_state(nullptr)
{
}

cppcoro::cancellation_token::cancellation_token(const cancellation_token& other) noexcept
	: m_state(other.m_state)
{
	if (m_state != nullptr)
	{
		m_state->add_token_ref();
	}
}

cppcoro::cancellation_token::cancellation_token(cancellation_token&& other) noexcept
	: m_state(other.m_state)
{
	other.m_state = nullptr;
}

cppcoro::cancellation_token::~cancellation_token()
{
	if (m_state != nullptr)
	{
		m_state->release_token_ref();
	}
}

cppcoro::cancellation_token& cppcoro::cancellation_token::operator=(const cancellation_token& other) noexcept
{
	if (other.m_state != m_state)
	{
		if (m_state != nullptr)
		{
			m_state->release_token_ref();
		}

		m_state = other.m_state;

		if (m_state != nullptr)
		{
			m_state->add_token_ref();
		}
	}

	return *this;
}

cppcoro::cancellation_token& cppcoro::cancellation_token::operator=(cancellation_token&& other) noexcept
{
	if (this != &other)
	{
		if (m_state != nullptr)
		{
			m_state->release_token_ref();
		}

		m_state = other.m_state;
		other.m_state = nullptr;
	}

	return *this;
}

void cppcoro::cancellation_token::swap(cancellation_token& other) noexcept
{
	std::swap(m_state, other.m_state);
}

bool cppcoro::cancellation_token::can_be_cancelled() const noexcept
{
	return m_state != nullptr && m_state->can_be_cancelled();
}

bool cppcoro::cancellation_token::is_cancellation_requested() const noexcept
{
	return m_state != nullptr && m_state->is_cancellation_requested();
}

void cppcoro::cancellation_token::throw_if_cancellation_requested() const
{
	if (is_cancellation_requested())
	{
		throw operation_cancelled{};
	}
}

cppcoro::cancellation_token::cancellation_token(detail::cancellation_state* state) noexcept
	: m_state(state)
{
	if (m_state != nullptr)
	{
		m_state->add_token_ref();
	}
}
