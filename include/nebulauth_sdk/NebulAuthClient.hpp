#pragma once

#include <map>
#include <string>

#include <nlohmann/json.hpp>

#include "NebulAuthExceptions.hpp"
#include "NebulAuthTypes.hpp"

namespace nebulauth {

class NebulAuthClient {
public:
  explicit NebulAuthClient(NebulAuthClientOptions options);

  NebulAuthResponse verifyKey(const VerifyKeyInput& input) const;
  NebulAuthResponse authVerify(const AuthVerifyInput& input) const;
  NebulAuthResponse redeemKey(const RedeemKeyInput& input) const;
  NebulAuthResponse resetHwid(const ResetHwidInput& input) const;

  NebulAuthResponse post(
      const std::string& endpoint,
      const nlohmann::json& payload,
      const GenericPostOptions& options = {}) const;

private:
  NebulAuthClientOptions options_;
  std::string baseUrl_;
  std::string basePath_;

  NebulAuthResponse postInternal(
      const std::string& endpoint,
      const nlohmann::json& payload,
      const GenericPostOptions& options) const;

  std::map<std::string, std::string> buildAuthHeaders(
      const std::string& method,
      const std::string& url,
      const std::string& body,
      bool usePop,
      const std::optional<std::string>& accessToken,
      const std::optional<std::string>& popKey) const;

  std::map<std::string, std::string> buildSigningHeaders(
      const std::string& method,
      const std::string& url,
      const std::string& body,
      const std::string& secret) const;

  std::string canonicalPath(const std::string& url) const;
  std::string endpointUrl(const std::string& endpoint) const;

  static std::string sha256Hex(const std::string& input);
  static std::string hmacSha256Hex(const std::string& key, const std::string& input);
  static std::string randomBase64Url(std::size_t bytes);
  static nlohmann::json parseJsonOrError(const std::string& responseBody);
};

} // namespace nebulauth
