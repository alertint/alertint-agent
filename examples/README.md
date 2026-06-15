# Examples

| Example | What it shows |
|---|---|
| [`alertmanager.yml`](alertmanager.yml) | Minimal Alertmanager receiver + route that forwards alerts to the agent's webhook with a bearer token |
| [`rules/`](rules/) | Starter local rule pack: a known-issue rule, a correlation rule, and a baseline override. Load it with `rules.local_pack_dir` — see [`docs/rules-spec.md`](../docs/rules-spec.md) |
| [`mcp-clients/`](mcp-clients/) | Copy-paste MCP client configs for Claude Code, Cursor, and Windsurf |
| [`../docker/docker-compose.yaml`](../docker/docker-compose.yaml) | Full local stack: Alertmanager + Prometheus + AlertINT agent, wired together — the quickstart path |

## Using the example rule pack

```bash
cp -r examples/rules ./my-rules
```

```yaml
# config.yaml
rules:
  local_pack_dir: ./my-rules
```

Restart the agent; it logs one `rules: pack loaded` line per pack. Rules in
your pack override baseline rules with the same `id` and add new ones.
Validation errors name the rule id, field, and reason.
