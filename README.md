# NebulAuth C++ SDK

C++ SDK for NebulAuth runtime API with bearer auth, replay protection, and PoP request mode.

## Structure

- `include/nebulauth_sdk/` — public SDK headers
- `src/` — implementation
- `tests/` — unit/contract tests + env-gated live test

## Build

```bash
cmake -S . -B build
cmake --build build
```

## Install

```bash
cmake --install build --config Release --prefix "C:/nebulauth-sdk"
```

This installs the library, headers, and CMake export targets.

## Run tests

```bash
ctest --test-dir build --output-on-failure
```

## Live test (optional)

```bash
set NEBULAUTH_LIVE_TEST=1
set NEBULAUTH_BEARER_TOKEN=mk_at_...
set NEBULAUTH_SIGNING_SECRET=mk_sig_...
set NEBULAUTH_TEST_KEY=mk_live_...

ctest --test-dir build --output-on-failure -R live
```

## Quick usage

```cpp
#include <nebulauth_sdk/NebulAuthClient.hpp>

using namespace nebulauth;

int main() {
  NebulAuthClientOptions options;
  options.bearerToken = "mk_at_...";
  options.signingSecret = "mk_sig_...";
  options.serviceSlug = "your-service";
  options.replayProtection = ReplayProtectionMode::Strict;

  NebulAuthClient client(options);

  VerifyKeyInput input;
  input.key = "mk_live_...";
  input.requestId = "req-123";
  input.hwid = "WIN-DEVICE-12345";

  const auto response = client.verifyKey(input);
  return response.ok ? 0 : 1;
}
```
