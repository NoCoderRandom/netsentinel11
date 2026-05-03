#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <variant>

namespace netsentinel::engine {

enum class ErrorCode {
    ok = 0,
    invalid_input = 1,
    permission_denied = 2,
    adapter_unavailable = 3,
    cancelled = 4,
    timeout = 5,
    internal = 6
};

std::string to_string(ErrorCode code);

struct Error {
    ErrorCode code = ErrorCode::ok;
    std::string context;
    std::string details;
    std::string user_message;
};

inline Error make_error(ErrorCode code, std::string context, std::string details) {
    Error error;
    error.code = code;
    error.context = std::move(context);
    error.details = std::move(details);
    error.user_message = "Operation blocked safely: " + error.context + ". " + error.details;
    return error;
}

class ErrorResultException : public std::runtime_error {
public:
    explicit ErrorResultException(const Error& error)
        : std::runtime_error(error.user_message), error_(error) {}

    const Error& error() const {
        return error_;
    }

private:
    Error error_;
};

template <typename T>
class Result {
public:
    using value_type = T;
    static Result<T> ok(T value) {
        return Result<T>(std::in_place_type<T>, std::move(value));
    }

    static Result<T> fail(ErrorCode code, std::string context, std::string details) {
        return Result<T>(std::in_place_type<Error>, make_error(code, std::move(context), std::move(details)));
    }

    bool valid() const {
        return std::holds_alternative<T>(value_);
    }

    bool failed() const {
        return std::holds_alternative<Error>(value_);
    }

    const T& value() const {
        if (!valid()) {
            if (std::holds_alternative<Error>(value_)) {
                throw ErrorResultException(std::get<Error>(value_));
            }
            throw std::runtime_error("result has no value");
        }
        return std::get<T>(value_);
    }

    const Error& error() const {
        if (!failed()) {
            throw std::runtime_error("result has no error");
        }
        return std::get<Error>(value_);
    }

    operator bool() const {
        return valid();
    }

private:
    explicit Result(std::in_place_type_t<T>, T v) : value_(std::move(v)) {}
    explicit Result(std::in_place_type_t<Error>, Error error) : value_(std::move(error)) {}

    std::variant<T, Error> value_;
};

} // namespace netsentinel::engine
