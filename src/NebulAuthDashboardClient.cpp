#include <nebulauth_sdk/NebulAuthDashboardClient.hpp>

#include <chrono>
#include <cctype>
#include <cstdint>
#include <iomanip>
#include <httplib.h>
#include <optional>
#include <sstream>
#include <utility>

namespace nebulauth {

namespace {

std::string trimTrailingSlash(const std::string& value) {
  if (value.size() > 1 && value.back() == '/') {
    return value.substr(0, value.size() - 1);
  }
  return value;
}

struct ParsedUrl {
  std::string scheme;
  std::string host;
  int port = 0;
  std::string path;
};

std::optional<ParsedUrl> parseUrl(const std::string& url) {
  const auto schemePos = url.find("://");
  if (schemePos == std::string::npos) {
    return std::nullopt;
  }

  ParsedUrl parsed;
  parsed.scheme = url.substr(0, schemePos);

  const auto authorityStart = schemePos + 3;
  const auto pathStart = url.find('/', authorityStart);
  const auto authority =
      pathStart == std::string::npos ? url.substr(authorityStart)
                                     : url.substr(authorityStart, pathStart - authorityStart);

  parsed.path = pathStart == std::string::npos ? "/" : url.substr(pathStart);

  const auto colonPos = authority.rfind(':');
  if (colonPos != std::string::npos) {
    parsed.host = authority.substr(0, colonPos);
    const auto portStr = authority.substr(colonPos + 1);
    try {
      parsed.port = std::stoi(portStr);
    } catch (...) {
      return std::nullopt;
    }
  } else {
    parsed.host = authority;
    parsed.port = parsed.scheme == "https" ? 443 : 80;
  }

  if (parsed.host.empty()) {
    return std::nullopt;
  }

  return parsed;
}

std::string encodePathParam(const std::string& value) {
  std::ostringstream out;
  for (const unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out << c;
    } else {
      out << '%' << std::uppercase << std::hex << static_cast<int>(c) << std::nouppercase << std::dec;
    }
  }
  return out.str();
}

} // namespace

NebulAuthDashboardClient::NebulAuthDashboardClient(NebulAuthDashboardClientOptions options)
    : options_(std::move(options)) {
  if (options_.baseUrl.empty()) {
    options_.baseUrl = "https://api.nebulauth.com/dashboard";
  }
  baseUrl_ = trimTrailingSlash(options_.baseUrl);
}

NebulAuthResponse NebulAuthDashboardClient::login(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/auth/login", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::logout(const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/auth/logout", nlohmann::json::object(), options);
}

NebulAuthResponse NebulAuthDashboardClient::me(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/me", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::getCustomer(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/customer", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::updateCustomer(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("PATCH", "/customer", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::createUser(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/users", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::listUsers(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/users", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::updateUser(const std::string& userId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("PATCH", "/users/" + encodePathParam(userId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::deleteUser(const std::string& userId, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/users/" + encodePathParam(userId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::createKey(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/keys", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::bulkCreateKeys(const nlohmann::json& payload, const std::string& format, const DashboardRequestOptions& options) const {
  DashboardRequestOptions merged = options;
  merged.query["format"] = format;
  return requestInternal("POST", "/keys/batch", payload, merged);
}

NebulAuthResponse NebulAuthDashboardClient::extendKeyDurations(int hours, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/keys/extend-duration", nlohmann::json{{"hours", hours}}, options);
}

NebulAuthResponse NebulAuthDashboardClient::getKey(const std::string& keyId, const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/keys/" + encodePathParam(keyId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::listKeys(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/keys", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::updateKey(const std::string& keyId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("PATCH", "/keys/" + encodePathParam(keyId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::resetKeyHwid(const std::string& keyId, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/keys/" + encodePathParam(keyId) + "/reset-hwid", nlohmann::json::object(), options);
}

NebulAuthResponse NebulAuthDashboardClient::deleteKey(const std::string& keyId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/keys/" + encodePathParam(keyId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::listKeySessions(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/key-sessions", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::revokeKeySession(const std::string& sessionId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/key-sessions/" + encodePathParam(sessionId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::revokeAllKeySessions(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/key-sessions/revoke-all", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::listCheckpoints(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/checkpoints", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::getCheckpoint(const std::string& checkpointId, const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/checkpoints/" + encodePathParam(checkpointId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::createCheckpoint(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/checkpoints", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::updateCheckpoint(const std::string& checkpointId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("PATCH", "/checkpoints/" + encodePathParam(checkpointId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::deleteCheckpoint(const std::string& checkpointId, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/checkpoints/" + encodePathParam(checkpointId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::listBlacklist(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/blacklist", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::createBlacklistEntry(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/blacklist", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::deleteBlacklistEntry(const std::string& blacklistId, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/blacklist/" + encodePathParam(blacklistId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::createApiToken(const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("POST", "/api-tokens", payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::updateApiToken(const std::string& tokenId, const nlohmann::json& payload, const DashboardRequestOptions& options) const {
  return requestInternal("PATCH", "/api-tokens/" + encodePathParam(tokenId), payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::listApiTokens(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/api-tokens", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::deleteApiToken(const std::string& tokenId, const DashboardRequestOptions& options) const {
  return requestInternal("DELETE", "/api-tokens/" + encodePathParam(tokenId), std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::analyticsSummary(std::optional<int> days, const DashboardRequestOptions& options) const {
  DashboardRequestOptions merged = options;
  if (days.has_value()) {
    merged.query["days"] = std::to_string(days.value());
  }
  return requestInternal("GET", "/analytics/summary", std::nullopt, merged);
}

NebulAuthResponse NebulAuthDashboardClient::analyticsGeo(std::optional<int> days, const DashboardRequestOptions& options) const {
  DashboardRequestOptions merged = options;
  if (days.has_value()) {
    merged.query["days"] = std::to_string(days.value());
  }
  return requestInternal("GET", "/analytics/geo", std::nullopt, merged);
}

NebulAuthResponse NebulAuthDashboardClient::analyticsActivity(const DashboardRequestOptions& options) const {
  return requestInternal("GET", "/analytics/activity", std::nullopt, options);
}

NebulAuthResponse NebulAuthDashboardClient::request(
    const std::string& method,
    const std::string& endpoint,
    const std::optional<nlohmann::json>& payload,
    const DashboardRequestOptions& options) const {
  return requestInternal(method, endpoint, payload, options);
}

NebulAuthResponse NebulAuthDashboardClient::requestInternal(
    const std::string& method,
    const std::string& endpoint,
    const std::optional<nlohmann::json>& payload,
    const DashboardRequestOptions& options) const {
  const auto url = endpointUrl(endpoint, options.query);
  const auto parsedUrl = parseUrl(url);
  if (!parsedUrl.has_value()) {
    throw NebulAuthConfigError("Invalid dashboard URL: " + url);
  }

  const bool hasBody = payload.has_value() && method != "GET";
  const std::string body = hasBody ? payload.value().dump() : "";

  httplib::Headers headers;
  if (hasBody) {
    headers.emplace("Content-Type", "application/json");
  }

  const auto auth = options.auth.has_value() ? options.auth : options_.auth;
  if (auth.has_value()) {
    if (auth->mode == DashboardAuthMode::Session) {
      if (!auth->sessionCookie.has_value() || auth->sessionCookie->empty()) {
        throw NebulAuthConfigError("sessionCookie is required for session auth mode");
      }
      headers.emplace("Cookie", "mc_session=" + auth->sessionCookie.value());
    } else {
      if (!auth->bearerToken.has_value() || auth->bearerToken->empty()) {
        throw NebulAuthConfigError("bearerToken is required for bearer auth mode");
      }
      headers.emplace("Authorization", "Bearer " + auth->bearerToken.value());
    }
  }

  for (const auto& [key, value] : options.extraHeaders) {
    headers.emplace(key, value);
  }

  httplib::Result response;
  if (parsedUrl->scheme == "https") {
    httplib::SSLClient client(parsedUrl->host, parsedUrl->port);
    client.enable_server_certificate_verification(true);
    client.set_connection_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_read_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_write_timeout(std::chrono::milliseconds(options_.timeoutMs));

    if (method == "GET") {
      response = client.Get(parsedUrl->path.c_str(), headers);
    } else if (method == "POST") {
      response = client.Post(parsedUrl->path.c_str(), headers, body, "application/json");
    } else if (method == "PATCH") {
      response = client.Patch(parsedUrl->path.c_str(), headers, body, "application/json");
    } else if (method == "DELETE") {
      response = client.Delete(parsedUrl->path.c_str(), headers, body, "application/json");
    } else {
      throw NebulAuthConfigError("Unsupported dashboard method: " + method);
    }
  } else {
    httplib::Client client(parsedUrl->host, parsedUrl->port);
    client.set_connection_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_read_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_write_timeout(std::chrono::milliseconds(options_.timeoutMs));

    if (method == "GET") {
      response = client.Get(parsedUrl->path.c_str(), headers);
    } else if (method == "POST") {
      response = client.Post(parsedUrl->path.c_str(), headers, body, "application/json");
    } else if (method == "PATCH") {
      response = client.Patch(parsedUrl->path.c_str(), headers, body, "application/json");
    } else if (method == "DELETE") {
      response = client.Delete(parsedUrl->path.c_str(), headers, body, "application/json");
    } else {
      throw NebulAuthConfigError("Unsupported dashboard method: " + method);
    }
  }

  if (!response) {
    throw NebulAuthRequestError("Dashboard HTTP request failed");
  }

  NebulAuthResponse sdkResponse;
  sdkResponse.statusCode = response->status;
  sdkResponse.ok = response->status >= 200 && response->status < 300;
  sdkResponse.data = parseJsonOrText(response->body);
  for (const auto& [key, value] : response->headers) {
    sdkResponse.headers[key] = value;
  }
  return sdkResponse;
}

std::string NebulAuthDashboardClient::endpointUrl(const std::string& endpoint, const std::map<std::string, std::string>& query) const {
  std::string url;
  if (endpoint.rfind("http://", 0) == 0 || endpoint.rfind("https://", 0) == 0) {
    url = endpoint;
  } else if (!endpoint.empty() && endpoint.front() == '/') {
    url = baseUrl_ + endpoint;
  } else {
    url = baseUrl_ + "/" + endpoint;
  }

  if (query.empty()) {
    return url;
  }

  std::ostringstream qs;
  bool first = true;
  for (const auto& [key, value] : query) {
    if (!first) {
      qs << '&';
    }
    first = false;
    qs << urlEncode(key) << '=' << urlEncode(value);
  }

  return url + "?" + qs.str();
}

std::string NebulAuthDashboardClient::urlEncode(const std::string& value) {
  std::ostringstream escaped;
  escaped.fill('0');
  escaped << std::hex;

  for (const unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      escaped << c;
    } else {
      escaped << '%' << std::uppercase << std::setw(2) << static_cast<int>(c) << std::nouppercase;
    }
  }

  return escaped.str();
}

nlohmann::json NebulAuthDashboardClient::parseJsonOrText(const std::string& responseBody) {
  try {
    return nlohmann::json::parse(responseBody);
  } catch (...) {
    return nlohmann::json(responseBody);
  }
}

} // namespace nebulauth
