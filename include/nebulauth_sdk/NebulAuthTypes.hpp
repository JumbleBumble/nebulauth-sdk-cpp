#pragma once

#include <map>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

namespace nebulauth {

enum class ReplayProtectionMode {
  None,
  Nonce,
  Strict,
};

struct NebulAuthClientOptions {
  std::string baseUrl = "https://api.nebulauth.com/api/v1";
  std::optional<std::string> bearerToken;
  std::optional<std::string> signingSecret;
  std::optional<std::string> serviceSlug;
  ReplayProtectionMode replayProtection = ReplayProtectionMode::Strict;
  int timeoutMs = 15000;
};

struct NebulAuthResponse {
  int statusCode = 0;
  bool ok = false;
  nlohmann::json data = nlohmann::json::object();
  std::map<std::string, std::string> headers;
};

struct VerifyKeyInput {
  std::string key;
  std::optional<std::string> requestId;
  std::optional<std::string> hwid;
  bool usePop = false;
  std::optional<std::string> accessToken;
  std::optional<std::string> popKey;
};

struct AuthVerifyInput {
  std::string key;
  std::optional<std::string> hwid;
  std::optional<std::string> requestId;
};

struct RedeemKeyInput {
  std::string key;
  std::string discordId;
  std::optional<std::string> serviceSlug;
  std::optional<std::string> requestId;
  bool usePop = false;
  std::optional<std::string> accessToken;
  std::optional<std::string> popKey;
};

struct ResetHwidInput {
  std::optional<std::string> discordId;
  std::optional<std::string> key;
  std::optional<std::string> requestId;
  bool usePop = false;
  std::optional<std::string> accessToken;
  std::optional<std::string> popKey;
};

struct GenericPostOptions {
  bool usePop = false;
  std::optional<std::string> accessToken;
  std::optional<std::string> popKey;
  std::map<std::string, std::string> extraHeaders;
};

} // namespace nebulauth
