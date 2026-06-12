---
title: "FAQ"
description: "Frequently asked questions about AlertINT."
section: "Concepts"
order: 3
slug: "faq"
---

# FAQ

Short answers for the decisions that matter before you install it.

## Do I have to host it myself?

Yes — **AlertINT** is self-hosted. It runs as a single binary with local
state, so your alert data stays with you.

---

## Does it replace Alertmanager?

No. Alertmanager still routes and manages alerts. **AlertINT** receives a
webhook copy and builds investigation context.

---

## Does it create silences or change routing?

No. **AlertINT** never changes Alertmanager, Kubernetes, or your
infrastructure — see [Scope and limits](scope-and-limits.md).

---

## Why MCP?

Because engineers increasingly investigate through agentic tools. MCP lets
those tools inspect **AlertINT** state and query telemetry without
copy-pasting alert text into chat.

---

## Why Prometheus?

Alert payloads alone are shallow. Prometheus queries let the connected
agent inspect metrics around the incident window.

---

## Can it remediate incidents?

No. **AlertINT** observes and reports. Operator-controlled,
approval-gated write workflows are a far-future direction.
