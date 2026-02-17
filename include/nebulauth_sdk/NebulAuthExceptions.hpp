#pragma once

#include <stdexcept>
#include <string>

namespace nebulauth {

class NebulAuthException : public std::runtime_error {
public:
  explicit NebulAuthException(const std::string& message)
      : std::runtime_error(message) {}
};

class NebulAuthConfigError : public NebulAuthException {
public:
  explicit NebulAuthConfigError(const std::string& message)
      : NebulAuthException(message) {}
};

class NebulAuthRequestError : public NebulAuthException {
public:
  explicit NebulAuthRequestError(const std::string& message)
      : NebulAuthException(message) {}
};

} // namespace nebulauth
