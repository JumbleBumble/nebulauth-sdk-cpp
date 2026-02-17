#include <nebulauth_sdk/NebulAuthClient.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <httplib.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <optional>
#include <random>
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

std::string extractPathFromUrl(const std::string& url) {
  const auto schemePos = url.find("://");
  if (schemePos == std::string::npos) {
    return "/";
  }

  const auto pathStart = url.find('/', schemePos + 3);
  if (pathStart == std::string::npos) {
    return "/";
  }

  auto path = url.substr(pathStart);
  const auto queryPos = path.find('?');
  if (queryPos != std::string::npos) {
    path = path.substr(0, queryPos);
  }
  if (path.empty()) {
    return "/";
  }
  return path;
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

  parsed.path =
      pathStart == std::string::npos ? "/" : url.substr(pathStart);

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

std::int64_t nowMillis() {
  const auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(
      std::chrono::system_clock::now());
  return now.time_since_epoch().count();
}

char nibbleToHex(std::uint8_t nibble) {
  if (nibble < 10U) {
    return static_cast<char>('0' + nibble);
  }
  return static_cast<char>('a' + (nibble - 10U));
}

std::string bytesToHex(const unsigned char* bytes, std::size_t length) {
  std::string out;
  out.resize(length * 2);
  for (std::size_t i = 0; i < length; ++i) {
    const auto high = static_cast<std::uint8_t>((bytes[i] >> 4) & 0x0F);
    const auto low = static_cast<std::uint8_t>(bytes[i] & 0x0F);
    out[i * 2] = nibbleToHex(high);
    out[i * 2 + 1] = nibbleToHex(low);
  }
  return out;
}

} // namespace

NebulAuthClient::NebulAuthClient(NebulAuthClientOptions options)
    : options_(std::move(options)) {
  if (options_.baseUrl.empty()) {
    options_.baseUrl = "https://api.nebulauth.com/api/v1";
  }

  baseUrl_ = trimTrailingSlash(options_.baseUrl);
  basePath_ = trimTrailingSlash(extractPathFromUrl(baseUrl_));
  if (basePath_.empty()) {
    basePath_ = "/";
  }
}

NebulAuthResponse NebulAuthClient::verifyKey(const VerifyKeyInput& input) const {
  nlohmann::json payload = {
      {"key", input.key},
  };
  if (input.requestId.has_value()) {
    payload["requestId"] = input.requestId.value();
  }

  GenericPostOptions options;
  options.usePop = input.usePop;
  options.accessToken = input.accessToken;
  options.popKey = input.popKey;
  if (input.hwid.has_value()) {
    options.extraHeaders["X-HWID"] = input.hwid.value();
  }

  return postInternal("/keys/verify", payload, options);
}

NebulAuthResponse NebulAuthClient::authVerify(const AuthVerifyInput& input) const {
  nlohmann::json payload = {
      {"key", input.key},
  };
  if (input.hwid.has_value()) {
    payload["hwid"] = input.hwid.value();
  }
  if (input.requestId.has_value()) {
    payload["requestId"] = input.requestId.value();
  }

  return postInternal("/auth/verify", payload, GenericPostOptions{});
}

NebulAuthResponse NebulAuthClient::redeemKey(const RedeemKeyInput& input) const {
  std::optional<std::string> slug = input.serviceSlug;
  if (!slug.has_value()) {
    slug = options_.serviceSlug;
  }
  if (!slug.has_value() || slug->empty()) {
    throw NebulAuthConfigError(
        "serviceSlug is required either in constructor options or redeemKey input");
  }

  nlohmann::json payload = {
      {"key", input.key},
      {"discordId", input.discordId},
      {"serviceSlug", slug.value()},
  };
  if (input.requestId.has_value()) {
    payload["requestId"] = input.requestId.value();
  }

  GenericPostOptions options;
  options.usePop = input.usePop;
  options.accessToken = input.accessToken;
  options.popKey = input.popKey;

  return postInternal("/keys/redeem", payload, options);
}

NebulAuthResponse NebulAuthClient::resetHwid(const ResetHwidInput& input) const {
  if (!input.discordId.has_value() && !input.key.has_value()) {
    throw NebulAuthConfigError("resetHwid requires at least discordId or key");
  }

  nlohmann::json payload = nlohmann::json::object();
  if (input.discordId.has_value()) {
    payload["discordId"] = input.discordId.value();
  }
  if (input.key.has_value()) {
    payload["key"] = input.key.value();
  }
  if (input.requestId.has_value()) {
    payload["requestId"] = input.requestId.value();
  }

  GenericPostOptions options;
  options.usePop = input.usePop;
  options.accessToken = input.accessToken;
  options.popKey = input.popKey;

  return postInternal("/keys/reset-hwid", payload, options);
}

NebulAuthResponse NebulAuthClient::post(
    const std::string& endpoint,
    const nlohmann::json& payload,
    const GenericPostOptions& options) const {
  return postInternal(endpoint, payload, options);
}

NebulAuthResponse NebulAuthClient::postInternal(
    const std::string& endpoint,
    const nlohmann::json& payload,
    const GenericPostOptions& options) const {
  const auto url = endpointUrl(endpoint);
  const auto body = payload.dump();
  const auto parsedUrl = parseUrl(url);
  if (!parsedUrl.has_value()) {
    throw NebulAuthConfigError("Invalid request URL: " + url);
  }

  httplib::Headers headers;
  headers.emplace("Content-Type", "application/json");

  const auto authHeaders = buildAuthHeaders(
      "POST",
      url,
      body,
      options.usePop,
      options.accessToken,
      options.popKey);
  for (const auto& [key, value] : authHeaders) {
    headers.emplace(key, value);
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
    response = client.Post(parsedUrl->path.c_str(), headers, body, "application/json");
  } else {
    httplib::Client client(parsedUrl->host, parsedUrl->port);
    client.set_connection_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_read_timeout(std::chrono::milliseconds(options_.timeoutMs));
    client.set_write_timeout(std::chrono::milliseconds(options_.timeoutMs));
    response = client.Post(parsedUrl->path.c_str(), headers, body, "application/json");
  }

  if (!response) {
    throw NebulAuthRequestError(
      "HTTP request failed (httplib error=" +
      std::to_string(static_cast<int>(response.error())) +
      ", url=" + url +
      ", host=" + parsedUrl->host +
      ", port=" + std::to_string(parsedUrl->port) +
      ", path=" + parsedUrl->path + ")");
  }

  NebulAuthResponse sdkResponse;
  sdkResponse.statusCode = response->status;
  sdkResponse.ok = response->status >= 200 && response->status < 300;
  sdkResponse.data = parseJsonOrError(response->body);
  for (const auto& [key, value] : response->headers) {
    sdkResponse.headers[key] = value;
  }
  return sdkResponse;
}

std::map<std::string, std::string> NebulAuthClient::buildAuthHeaders(
    const std::string& method,
    const std::string& url,
    const std::string& body,
    bool usePop,
    const std::optional<std::string>& accessToken,
    const std::optional<std::string>& popKey) const {
  if (usePop) {
    if (!accessToken.has_value() || accessToken->empty()) {
      throw NebulAuthConfigError("accessToken is required when usePop=true");
    }
    if (!popKey.has_value() || popKey->empty()) {
      throw NebulAuthConfigError("popKey is required when usePop=true");
    }

    auto headers = buildSigningHeaders(method, url, body, popKey.value());
    headers["Authorization"] = "Bearer " + accessToken.value();
    return headers;
  }

  if (!options_.bearerToken.has_value() || options_.bearerToken->empty()) {
    throw NebulAuthConfigError("bearerToken is required for bearer mode");
  }

  std::map<std::string, std::string> headers;
  headers["Authorization"] = "Bearer " + options_.bearerToken.value();

  if (options_.replayProtection != ReplayProtectionMode::None) {
    if (!options_.signingSecret.has_value() || options_.signingSecret->empty()) {
      throw NebulAuthConfigError(
          "signingSecret is required when replayProtection is nonce/strict");
    }

    auto signingHeaders =
        buildSigningHeaders(method, url, body, options_.signingSecret.value());

    if (options_.replayProtection == ReplayProtectionMode::Nonce) {
      signingHeaders.erase("X-Body-Sha256");
    }

    headers.insert(signingHeaders.begin(), signingHeaders.end());
  }

  return headers;
}

std::map<std::string, std::string> NebulAuthClient::buildSigningHeaders(
    const std::string& method,
    const std::string& url,
    const std::string& body,
    const std::string& secret) const {
  const auto path = canonicalPath(url);
  const auto timestamp = std::to_string(nowMillis());
  const auto nonce = randomBase64Url(16);
  const auto bodyHash = sha256Hex(body);

  const auto canonical =
      method + "\n" + path + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
  const auto signature = hmacSha256Hex(secret, canonical);

  return {
      {"X-Timestamp", timestamp},
      {"X-Nonce", nonce},
      {"X-Signature", signature},
      {"X-Body-Sha256", bodyHash},
  };
}

std::string NebulAuthClient::canonicalPath(const std::string& url) const {
  auto path = extractPathFromUrl(url);

  if (!basePath_.empty() && basePath_ != "/" && path.rfind(basePath_, 0) == 0) {
    path = path.substr(basePath_.size());
    if (path.empty()) {
      path = "/";
    }
  }

  if (path.front() != '/') {
    path = '/' + path;
  }
  return path;
}

std::string NebulAuthClient::endpointUrl(const std::string& endpoint) const {
  if (endpoint.empty()) {
    return baseUrl_;
  }

  if (endpoint.rfind("http://", 0) == 0 || endpoint.rfind("https://", 0) == 0) {
    return endpoint;
  }

  if (endpoint.front() == '/') {
    return baseUrl_ + endpoint;
  }

  return baseUrl_ + "/" + endpoint;
}

std::string NebulAuthClient::sha256Hex(const std::string& input) {
  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256(
      reinterpret_cast<const unsigned char*>(input.data()),
      input.size(),
      hash);
  return bytesToHex(hash, SHA256_DIGEST_LENGTH);
}

std::string NebulAuthClient::hmacSha256Hex(const std::string& key, const std::string& input) {
  unsigned int len = SHA256_DIGEST_LENGTH;
  unsigned char hash[SHA256_DIGEST_LENGTH];

  HMAC(
      EVP_sha256(),
      reinterpret_cast<const unsigned char*>(key.data()),
      static_cast<int>(key.size()),
      reinterpret_cast<const unsigned char*>(input.data()),
      input.size(),
      hash,
      &len);

  return bytesToHex(hash, len);
}

std::string NebulAuthClient::randomBase64Url(std::size_t bytes) {
  std::string randomBytes;
  randomBytes.resize(bytes);

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<int> dist(0, 255);

  for (std::size_t i = 0; i < bytes; ++i) {
    randomBytes[i] = static_cast<char>(dist(gen));
  }

  static const char* base64Chars =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  std::string encoded;
  int val = 0;
  int valb = -6;
  for (unsigned char c : randomBytes) {
    val = (val << 8) + c;
    valb += 8;
    while (valb >= 0) {
      encoded.push_back(base64Chars[(val >> valb) & 0x3F]);
      valb -= 6;
    }
  }
  if (valb > -6) {
    encoded.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
  }

  std::replace(encoded.begin(), encoded.end(), '+', '-');
  std::replace(encoded.begin(), encoded.end(), '/', '_');
  return encoded;
}

nlohmann::json NebulAuthClient::parseJsonOrError(const std::string& responseBody) {
  if (responseBody.empty()) {
    return nlohmann::json::object();
  }

  try {
    return nlohmann::json::parse(responseBody);
  } catch (...) {
    return nlohmann::json{{"error", responseBody}};
  }
}

} // namespace nebulauth
