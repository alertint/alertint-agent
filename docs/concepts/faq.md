---
title: "FAQ"
description: "Frequently asked questions about AlertINT."
section: "Concepts"
order: 3
slug: "faq"
---

# FAQ

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

---

## Is AlertINT open source? What is "Fair Source"?

**AlertINT** is **[Fair Source](https://fair.io)**. Fair Source is a
publishing model — pioneered by Sentry and others — where the code is
public to read, use, modify, and self-host, with one narrow restriction
(you can't repackage it as a competing commercial offering) that lifts on
a fixed schedule.

Concretely, **AlertINT** is licensed under
[FSL-1.1-ALv2](https://fsl.software) (the Functional Source License), and
**every release automatically converts to the Apache 2.0 open source
license two years after it ships**. So it is not OSI "open source" on day
one, but each version becomes fully open source on a predictable timeline —
a practice called Delayed Open Source Publication.
