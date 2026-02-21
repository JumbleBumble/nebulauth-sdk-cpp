#include <catch2/catch_test_macros.hpp>
#include <httplib.h>

#include <chrono>
#include <nebulauth_sdk/NebulAuthDashboardClient.hpp>
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

TEST_CASE("dashboard me sends bearer auth header") {
  TestServer ts;
  ts.server.Get("/dashboard/me", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE(req.get_header_value("Authorization") == "Bearer mk_at_test");
    res.status = 200;
    res.set_content(R"({"id":"user-1"})", "application/json");
  });
  ts.start();

  NebulAuthDashboardClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/dashboard";
  DashboardAuthOptions auth;
  auth.mode = DashboardAuthMode::Bearer;
  auth.sessionCookie = std::nullopt;
  auth.bearerToken = std::string("mk_at_test");
  options.auth = auth;

  NebulAuthDashboardClient client(options);
  const auto response = client.me();

  REQUIRE(response.ok);
  REQUIRE(response.data["id"] == "user-1");
}

TEST_CASE("dashboard list users sends session cookie") {
  TestServer ts;
  ts.server.Get("/dashboard/users", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE(req.get_header_value("Cookie") == "mc_session=sess-123");
    res.status = 200;
    res.set_content("[]", "application/json");
  });
  ts.start();

  NebulAuthDashboardClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/dashboard";
  DashboardAuthOptions auth;
  auth.mode = DashboardAuthMode::Session;
  auth.sessionCookie = std::string("sess-123");
  auth.bearerToken = std::nullopt;
  options.auth = auth;

  NebulAuthDashboardClient client(options);
  const auto response = client.listUsers();

  REQUIRE(response.ok);
}

TEST_CASE("analytics summary includes days query") {
  TestServer ts;
  ts.server.Get("/dashboard/analytics/summary", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE(req.has_param("days"));
    REQUIRE(req.get_param_value("days") == "30");
    res.status = 200;
    res.set_content(R"({"totals":{}})", "application/json");
  });
  ts.start();

  NebulAuthDashboardClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/dashboard";
  DashboardAuthOptions auth;
  auth.mode = DashboardAuthMode::Bearer;
  auth.sessionCookie = std::nullopt;
  auth.bearerToken = std::string("mk_at_test");
  options.auth = auth;

  NebulAuthDashboardClient client(options);
  const auto response = client.analyticsSummary(30);

  REQUIRE(response.ok);
}

TEST_CASE("bulk create keys uses format query") {
  TestServer ts;
  ts.server.Post("/dashboard/keys/batch", [](const httplib::Request& req, httplib::Response& res) {
    REQUIRE(req.has_param("format"));
    REQUIRE(req.get_param_value("format") == "txt");
    res.status = 200;
    res.set_content("key-1", "text/plain");
  });
  ts.start();

  NebulAuthDashboardClientOptions options;
  options.baseUrl = "http://127.0.0.1:" + std::to_string(ts.port) + "/dashboard";
  DashboardAuthOptions auth;
  auth.mode = DashboardAuthMode::Bearer;
  auth.sessionCookie = std::nullopt;
  auth.bearerToken = std::string("mk_at_test");
  options.auth = auth;

  NebulAuthDashboardClient client(options);
  const auto response = client.bulkCreateKeys(nlohmann::json{{"count", 1}, {"labelPrefix", "Promo"}}, "txt");

  REQUIRE(response.statusCode == 200);
}

TEST_CASE("session auth requires cookie") {
  NebulAuthDashboardClientOptions options;
  options.baseUrl = "http://127.0.0.1:12345/dashboard";
  DashboardAuthOptions auth;
  auth.mode = DashboardAuthMode::Session;
  auth.sessionCookie = std::nullopt;
  auth.bearerToken = std::nullopt;
  options.auth = auth;

  NebulAuthDashboardClient client(options);

  REQUIRE_THROWS_AS(client.me(), NebulAuthConfigError);
}
