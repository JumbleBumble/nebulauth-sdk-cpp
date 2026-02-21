#pragma once

#include <map>
#include <optional>
#include <string>

#include <nlohmann/json.hpp>

#include "NebulAuthExceptions.hpp"
#include "NebulAuthTypes.hpp"

namespace nebulauth {

enum class DashboardAuthMode {
  Session,
  Bearer,
};

struct DashboardAuthOptions {
  DashboardAuthMode mode = DashboardAuthMode::Session;
  std::optional<std::string> sessionCookie;
  std::optional<std::string> bearerToken;
};

struct DashboardRequestOptions {
  std::optional<DashboardAuthOptions> auth;
  std::map<std::string, std::string> query;
  std::map<std::string, std::string> extraHeaders;
};

struct NebulAuthDashboardClientOptions {
  std::string baseUrl = "https://api.nebulauth.com/dashboard";
  std::optional<DashboardAuthOptions> auth;
  int timeoutMs = 15000;
};

class NebulAuthDashboardClient {
public:
  explicit NebulAuthDashboardClient(NebulAuthDashboardClientOptions options = {});

  NebulAuthResponse login(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse logout(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse me(const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse getCustomer(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse updateCustomer(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse createUser(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse listUsers(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse updateUser(const std::string& userId, const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse deleteUser(const std::string& userId, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse createKey(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse bulkCreateKeys(const nlohmann::json& payload, const std::string& format = "json", const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse extendKeyDurations(int hours, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse getKey(const std::string& keyId, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse listKeys(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse updateKey(const std::string& keyId, const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse resetKeyHwid(const std::string& keyId, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse deleteKey(const std::string& keyId, const nlohmann::json& payload = nlohmann::json::object(), const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse listKeySessions(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse revokeKeySession(const std::string& sessionId, const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse revokeAllKeySessions(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse listCheckpoints(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse getCheckpoint(const std::string& checkpointId, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse createCheckpoint(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse updateCheckpoint(const std::string& checkpointId, const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse deleteCheckpoint(const std::string& checkpointId, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse listBlacklist(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse createBlacklistEntry(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse deleteBlacklistEntry(const std::string& blacklistId, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse createApiToken(const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse updateApiToken(const std::string& tokenId, const nlohmann::json& payload, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse listApiTokens(const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse deleteApiToken(const std::string& tokenId, const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse analyticsSummary(std::optional<int> days = std::nullopt, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse analyticsGeo(std::optional<int> days = std::nullopt, const DashboardRequestOptions& options = {}) const;
  NebulAuthResponse analyticsActivity(const DashboardRequestOptions& options = {}) const;

  NebulAuthResponse request(
      const std::string& method,
      const std::string& endpoint,
      const std::optional<nlohmann::json>& payload,
      const DashboardRequestOptions& options = {}) const;

private:
  NebulAuthDashboardClientOptions options_;
  std::string baseUrl_;

  NebulAuthResponse requestInternal(
      const std::string& method,
      const std::string& endpoint,
      const std::optional<nlohmann::json>& payload,
      const DashboardRequestOptions& options) const;

  std::string endpointUrl(const std::string& endpoint, const std::map<std::string, std::string>& query) const;
  static std::string urlEncode(const std::string& value);
  static nlohmann::json parseJsonOrText(const std::string& responseBody);
};

} // namespace nebulauth
