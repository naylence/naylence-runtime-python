# Naylence Fame Runtime

The **Fame Runtime** is the default runtime environment for the Naylence platform’s federated messaging fabric. It provides:

- Secure, attach-token-based admission and handshake
- Pluggable transport connector system
- Fully async FameNode lifecycle
- Node/routing orchestration
- Built-in service management and dynamic address binding
- RoutingNode with downstream routing and capability-based delivery

This runtime powers agents and routers in a Fame-enabled environment, integrating with the core protocol and FameEnvelope transport model.
---

## 🔧 Features

- **Pluggable Node Factory** via `NodeFactory`
- **RoutingNode** with dynamic downstream management
- **Admission/Attach flow** via:
  - NodeHello → NodeWelcome (admission)
  - NodeAttach → NodeAttachAck (handshake)
- **JWT or JWKS-based authorization** of attach requests
- **RoutingPolicy abstraction** (default: capability-aware fallback to hybrid path)
- **Flow control & backpressure** with credit windows
- **In-memory or custom pluggable KeyValueStore**
- **In-memory or HTTP-based admission service**
- **ServiceManager** with capability resolution
- **Support for WebSocket and custom transport connectors**

---
