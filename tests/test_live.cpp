#include <catch2/catch_test_macros.hpp>

#include <cstdlib>
#include <nebulauth_sdk/NebulAuthClient.hpp>

using namespace nebulauth;

namespace {
constexpr const char* kDefaultBaseUrl = "https://api.nebulauth.com/api/v1";
}

TEST_CASE("live verify key env-gated", "[live]") {
  const char* enabled = std::getenv("NEBULAUTH_LIVE_TEST");
  if (!enabled || std::string(enabled) != "1") {
    SUCCEED("Live test disabled. Set NEBULAUTH_LIVE_TEST=1 to enable.");
    return;
  }

  const char* baseUrl = std::getenv("NEBULAUTH_BASE_URL");
  const char* bearerToken = std::getenv("NEBULAUTH_BEARER_TOKEN");
  const char* testKey = std::getenv("NEBULAUTH_TEST_KEY");
  const char* signingSecret = std::getenv("NEBULAUTH_SIGNING_SECRET");
  const char* hwid = std::getenv("NEBULAUTH_TEST_HWID");

  REQUIRE(bearerToken != nullptr);
  REQUIRE(testKey != nullptr);

  NebulAuthClientOptions options;
  options.baseUrl = (baseUrl && std::string(baseUrl).size() > 0) ? baseUrl : kDefaultBaseUrl;
  options.bearerToken = bearerToken;
  if (signingSecret && std::string(signingSecret).size() > 0) {
    options.signingSecret = signingSecret;
    options.replayProtection = ReplayProtectionMode::Strict;
  } else {
    options.replayProtection = ReplayProtectionMode::None;
  }

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = testKey;
  input.requestId = "live-cpp-verify";
  if (hwid && std::string(hwid).size() > 0) {
    input.hwid = hwid;
  }

  const auto response = client.verifyKey(input);
  REQUIRE(response.data.is_object());
  REQUIRE(response.data.contains("valid"));
}
