# Leaderboard Agent (FINRA Benchmark)

This repository runs the FINRA short-interest benchmark and posts results to
AgentBeats via webhook. It evaluates a candidate purple agent by calling your
green agent, which orchestrates the assessment.

## Overview

- **Green agent image**: `ghcr.io/wczubal1/greenagentwitty:latest`
- **Candidate purple image**: provided by AgentBeats webhook payload
- **Test cases**: 2 cases, each with 5 symbols and different dates
- **Scoring**: pass/fail (all cases must pass)

## Required Secrets

Add these to GitHub repo secrets (Settings → Secrets and variables → Actions):

- `FINRA_CLIENT_ID`
- `FINRA_CLIENT_SECRET`
- `OPENAI_API_KEY`
- `OPENAI_MODEL` (optional)
- `AGENTBEATS_CALLBACK_URL` (from AgentBeats leaderboard config)
- `AGENTBEATS_CALLBACK_TOKEN` (from AgentBeats leaderboard config, if provided)

## How It Works

The workflow:
1. Pulls the green and purple images.
2. Starts both containers on a shared Docker network.
3. Runs two test cases through the green agent.
4. Sends results to the AgentBeats callback URL (including per-case duration).

## Local Run (Optional)

```bash
export FINRA_CLIENT_ID="..."
export FINRA_CLIENT_SECRET="..."
export OPENAI_API_KEY="..."

python scripts/run_benchmark.py \
  --green-image ghcr.io/wczubal1/greenagentwitty:latest \
  --purple-image ghcr.io/wczubal1/purpleagentwitty:latest
```

Enable MCP for the purple container (optional):

```bash
python scripts/run_benchmark.py \
  --green-image ghcr.io/wczubal1/greenagentwitty:latest \
  --purple-image ghcr.io/wczubal1/purpleagentwitty:latest \
  --use-mcp
```

## Notes

- `tools/client_short.py` and `tools/client.py` are copied from the brokercheck project.
- The benchmark mounts those tools to
  `/home/wczubal1/projects/tau2/brokercheck/client_short.py` inside the purple
  container to match the green agent's default path.
- `client.py` depends on the `requests` package; ensure the purple image has it.

## Leaderboard Queries (Optional)

Example query showing latency:

```json
[
  {
    "name": "Latest Runs",
    "query": "SELECT id, status, passed, total, total_duration_seconds, average_duration_seconds, created_at FROM results ORDER BY created_at DESC"
  }
]
```



## Scenario Template

The AgentBeats scenario definition lives in `scenario.toml`. Submitters fill in the
purple agent ID and secrets, while the green agent ID and default test cases are
pre-filled.

