#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <atomic>
#include <chrono>
#include <nebulauth_sdk/NebulAuthClient.hpp>
#include <thread>

using namespace nebulauth;

namespace {

struct TestServer {
  httplib::Server server;
  int port = 0;
  std::thread thread;

  void start() {
    port = server.bind_to_any_port("127.0.0.1");
    REQUIRE(port > 0);

    thread = std::thread([this]() {
      server.listen_after_bind();
    });

    for (int i = 0; i < 200 && !server.is_running(); ++i) {
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    REQUIRE(server.is_running());
  }

  void stop() {
    server.stop();
    if (thread.joinable()) {
      thread.join();
    }
  }

  ~TestServer() {
    stop();
  }
};

} // namespace

TEST_CASE("verifyKey sends bearer and hwid headers") {
  TestServer ts;
  ts.server.Post("/api/v1/keys/verify", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE(req.get_header_value("Authorization") == "Bearer mk_at_test");
    REQUIRE(req.get_header_value("X-HWID") == "HWID-1");
    auto body = nlohmann::json::parse(req.body);
    REQUIRE(body["key"] == "mk_live_test");
    REQUIRE(body["requestId"] == "req-1");

    res.status = 200;
    res.set_content(R"({"valid":true})", "application/json");
  });
  ts.start();

  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/api/v1";
  options.bearerToken = "mk_at_test";
  options.replayProtection = ReplayProtectionMode::None;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_test";
  input.requestId = "req-1";
  input.hwid = "HWID-1";

  const auto response = client.verifyKey(input);
  REQUIRE(response.statusCode == 200);
  REQUIRE(response.data["valid"] == true);
}

TEST_CASE("strict replay sends signing headers") {
  TestServer ts;
  ts.server.Post("/api/v1/keys/verify", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE_FALSE(req.get_header_value("X-Timestamp").empty());
    REQUIRE_FALSE(req.get_header_value("X-Nonce").empty());
    REQUIRE_FALSE(req.get_header_value("X-Signature").empty());
    REQUIRE_FALSE(req.get_header_value("X-Body-Sha256").empty());
    res.status = 200;
    res.set_content(R"({"valid":true})", "application/json");
  });
  ts.start();

  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/api/v1";
  options.bearerToken = "mk_at_test";
  options.signingSecret = "mk_sig_test";
  options.replayProtection = ReplayProtectionMode::Strict;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_test";
  const auto response = client.verifyKey(input);
  REQUIRE(response.ok);
}

TEST_CASE("nonce replay omits body hash header") {
  TestServer ts;
  ts.server.Post("/api/v1/keys/verify", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE_FALSE(req.get_header_value("X-Timestamp").empty());
    REQUIRE_FALSE(req.get_header_value("X-Nonce").empty());
    REQUIRE_FALSE(req.get_header_value("X-Signature").empty());
    REQUIRE(req.get_header_value("X-Body-Sha256").empty());
    res.status = 200;
    res.set_content(R"({"valid":true})", "application/json");
  });
  ts.start();

  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/api/v1";
  options.bearerToken = "mk_at_test";
  options.signingSecret = "mk_sig_test";
  options.replayProtection = ReplayProtectionMode::Nonce;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_test";
  const auto response = client.verifyKey(input);
  REQUIRE(response.ok);
}

TEST_CASE("pop mode requires token and key") {
  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:12345/api/v1";
  options.bearerToken = "mk_at_test";
  options.replayProtection = ReplayProtectionMode::None;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_test";
  input.usePop = true;

  REQUIRE_THROWS_AS(client.verifyKey(input), NebulAuthConfigError);
}

TEST_CASE("redeem requires service slug") {
  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:12345/api/v1";
  options.bearerToken = "mk_at_test";
  options.replayProtection = ReplayProtectionMode::None;

  NebulAuthClient client(options);

  RedeemKeyInput input;
  input.key = "mk_live_test";
  input.discordId = "123";

  REQUIRE_THROWS_AS(client.redeemKey(input), NebulAuthConfigError);
}

TEST_CASE("reset hwid requires discord or key") {
  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:12345/api/v1";
  options.bearerToken = "mk_at_test";
  options.replayProtection = ReplayProtectionMode::None;

  NebulAuthClient client(options);

  ResetHwidInput input;
  REQUIRE_THROWS_AS(client.resetHwid(input), NebulAuthConfigError);
}

TEST_CASE("non-json response falls back to error payload") {
  TestServer ts;
  ts.server.Post("/api/v1/keys/verify", [](const httplib::Request&, httplib::Response& res) {
    res.status = 400;
    res.set_content("something broke", "text/plain");
  });
  ts.start();

  NebulAuthClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/api/v1";
  options.bearerToken = "mk_at_test";
  options.replayProtection = ReplayProtectionMode::None;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_test";

  const auto response = client.verifyKey(input);
  REQUIRE_FALSE(response.ok);
  REQUIRE(response.data["error"] == "something broke");
}
