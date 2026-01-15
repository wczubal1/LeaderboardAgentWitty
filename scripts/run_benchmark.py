from __future__ import annotations

import argparse
import tomllib
import asyncio
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import httpx
from a2a.client import A2ACardResolver, ClientConfig, ClientFactory
from a2a.types import Message, Part, Role, TextPart


DEFAULT_GREEN_IMAGE = "ghcr.io/wczubal1/greenagentwitty:latest"
DEFAULT_PURPLE_IMAGE = "ghcr.io/wczubal1/purpleagentwitty:latest"
DEFAULT_CASES_PATH = Path(__file__).resolve().parents[1] / "test_cases.json"


def _run_command(cmd: list[str]) -> None:
    subprocess.run(cmd, check=True)


def _normalize_image(value: str | None, fallback: str) -> str:
    if not value:
        return fallback
    raw = str(value).strip()
    if not raw or raw.lower() in {"none", "null"}:
        return fallback
    lowered = raw.lower()
    for prefix in ("purple_image:", "green_image:", "image:"):
        if lowered.startswith(prefix):
            raw = raw.split(":", 1)[1].strip()
            break
    if " " in raw:
        raw = raw.replace(",", " ").split()[-1]
    return raw or fallback


def _start_container(
    *,
    name: str,
    image: str,
    port: int,
    network: str,
    env: dict[str, str] | None = None,
    mounts: list[str] | None = None,
    extra_args: list[str] | None = None,
) -> None:
    cmd = ["docker", "run", "-d", "--rm", "--name", name, "--network", network]
    cmd.extend(["-p", f"{port}:{port}"])
    if env:
        for key, value in env.items():
            if value:
                cmd.extend(["-e", f"{key}={value}"])
    if mounts:
        for mount in mounts:
            cmd.extend(["-v", mount])
    cmd.append(image)
    if extra_args:
        cmd.extend(extra_args)
    _run_command(cmd)


def _ensure_network(name: str) -> None:
    existing = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    if name not in existing:
        _run_command(["docker", "network", "create", name])


def _wait_for_url(url: str, timeout: int = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=2)
            if response.status_code == 200:
                return
        except httpx.HTTPError:
            time.sleep(1)
    raise RuntimeError(f"Timed out waiting for {url}")


def _load_scenario(path: Path) -> tuple[list[dict[str, object]], str | None, str | None]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    config = data.get("config") or {}
    cases = config.get("cases") or []
    if not isinstance(cases, list) or not cases:
        raise ValueError("scenario.toml must include config.cases list")

    green = data.get("green_agent") or {}
    green_id = green.get("agentbeats_id") or None

    purple_id = None
    for participant in data.get("participants", []) or []:
        if not isinstance(participant, dict):
            continue
        if participant.get("name") == "purple":
            purple_id = participant.get("agentbeats_id") or None
            break

    return cases, green_id, purple_id


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value).strip("-")
    return slug.lower() or "unknown"


def _write_results(payload: dict[str, object], results_dir: Path) -> Path:
    results_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    identifier = _slugify(str(payload.get("id", "unknown")))
    filename = f"{timestamp}_{identifier}.json"
    output_path = results_dir / filename
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return output_path


def _load_cases(path: Path) -> list[dict[str, object]]:
    if path.suffix == ".toml":
        cases, _, _ = _load_scenario(path)
        return cases
    payload = json.loads(path.read_text(encoding="utf-8"))
    cases = payload.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("test_cases.json must include a non-empty cases list")
    return [case for case in cases if isinstance(case, dict)]


async def _run_case(
    *,
    green_url: str,
    purple_url: str,
    config: dict[str, object],
    http_timeout: int,
    agent_id: str,
) -> dict[str, object]:
    start = time.monotonic()
    async with httpx.AsyncClient(timeout=http_timeout) as httpx_client:
        resolver = A2ACardResolver(httpx_client, green_url)
        card = await resolver.get_agent_card()
        client = ClientFactory(
            ClientConfig(httpx_client=httpx_client, streaming=False)
        ).create(card)

        payload = {
            "id": agent_id,
            "participants": {"purple": purple_url},
            "config": config,
        }
        msg = Message(
            kind="message",
            role=Role.user,
            message_id=uuid4().hex,
            parts=[Part(root=TextPart(text=json.dumps(payload)))],
        )
        events = [event async for event in client.send_message(msg)]
        result = _extract_result(events)
        result["duration_seconds"] = round(time.monotonic() - start, 3)
        return result


def _extract_result(events: list[object]) -> dict[str, object]:
    dumps: list[dict[str, object]] = []
    for event in events:
        if hasattr(event, "model_dump"):
            dumps.append(event.model_dump())
        elif isinstance(event, tuple) and len(event) == 2:
            task = event[0]
            if hasattr(task, "model_dump"):
                dumps.append({"kind": "task-update", "task": task.model_dump()})
            elif isinstance(task, dict):
                dumps.append({"kind": "task-update", "task": task})
        elif isinstance(event, dict):
            dumps.append(event)

    status_message = None
    for event in reversed(dumps):
        if event.get("kind") != "task-update":
            continue
        task = event.get("task") or {}
        status = task.get("status") or {}
        message = status.get("message") or {}
        parts = message.get("parts") or []
        texts = [
            part.get("text")
            for part in parts
            if part.get("kind") == "text" and part.get("text")
        ]
        if texts:
            status_message = " ".join(texts)
        break

    for event in reversed(dumps):
        if event.get("kind") != "task-update":
            continue
        task = event.get("task") or {}
        artifacts = task.get("artifacts") or []
        for artifact in artifacts:
            for part in artifact.get("parts", []):
                if part.get("kind") == "data":
                    data = part.get("data") or {}
                    status = str(data.get("status") or "")
                    return {
                        "status": status,
                        "data": data,
                    }
    error = {"error": "No result artifact found"}
    if status_message:
        error["status_message"] = status_message
    return {"status": "error", "data": error}


def _dump_container_logs(name: str) -> None:
    print(f"\n--- docker logs {name} ---")
    result = subprocess.run(
        ["docker", "logs", name],
        capture_output=True,
        text=True,
    )
    if result.stdout:
        print(result.stdout)
    if result.stderr:
        print(result.stderr)
    if result.returncode != 0:
        print(f"[warn] docker logs {name} failed with code {result.returncode}")


def _cleanup_container(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", name],
        check=False,
        capture_output=True,
        text=True,
    )


def _post_results(payload: dict[str, object]) -> None:
    url = os.environ.get("AGENTBEATS_CALLBACK_URL")
    if not url:
        print(json.dumps(payload, indent=2))
        return
    headers = {"Content-Type": "application/json"}
    token = os.environ.get("AGENTBEATS_CALLBACK_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    response = httpx.post(url, json=payload, headers=headers, timeout=30)
    response.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the FINRA leaderboard benchmark.")
    parser.add_argument("--green-image", default=DEFAULT_GREEN_IMAGE)
    parser.add_argument("--purple-image", default=DEFAULT_PURPLE_IMAGE)
    parser.add_argument("--cases", default=str(DEFAULT_CASES_PATH))
    parser.add_argument("--scenario", default=str(Path(__file__).resolve().parents[1] / "scenario.toml"))
    parser.add_argument("--http-timeout", type=int, default=180)
    parser.add_argument(
        "--use-mcp",
        action="store_true",
        help="Enable MCP server for FINRA tool calls inside the purple container.",
    )
    args = parser.parse_args()

    scenario_path = Path(args.scenario)
    scenario_cases = None
    green_id = None
    purple_id = None
    if scenario_path.exists():
        scenario_cases, green_id, purple_id = _load_scenario(scenario_path)


    green_image = _normalize_image(args.green_image, DEFAULT_GREEN_IMAGE)
    purple_image = _normalize_image(args.purple_image, DEFAULT_PURPLE_IMAGE)
    agent_id = purple_id or purple_image

    cases = scenario_cases or _load_cases(Path(args.cases))

    finra_client_id = os.environ.get("FINRA_CLIENT_ID", "")
    finra_client_secret = os.environ.get("FINRA_CLIENT_SECRET", "")
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    openai_model = os.environ.get("OPENAI_MODEL", "")

    green_id = green_id or os.environ.get("GREEN_AGENT_ID")
    purple_id = purple_id or os.environ.get("PURPLE_AGENT_ID")


    network = "agent-net"
    _ensure_network(network)

    tools_dir = Path(__file__).resolve().parents[1] / "tools"
    brokercheck_dir = "/home/wczubal1/projects/tau2/brokercheck"
    mounts = [
        f"{tools_dir}/client_short.py:{brokercheck_dir}/client_short.py:ro",
        f"{tools_dir}/client.py:{brokercheck_dir}/client.py:ro",
    ]

    _start_container(
        name="green",
        image=green_image,
        port=9009,
        network=network,
        extra_args=["--host", "0.0.0.0", "--port", "9009"],
    )
    purple_env = {
        "OPENAI_API_KEY": openai_key,
        "OPENAI_MODEL": openai_model,
    }
    if args.use_mcp:
        purple_env["MCP_SERVER_COMMAND"] = "python /opt/mcp_server.py"

    _start_container(
        name="purple",
        image=purple_image,
        port=9010,
        network=network,
        env=purple_env,
        mounts=mounts
        + [f"{tools_dir}/mcp_server.py:/opt/mcp_server.py:ro"],
        extra_args=["--host", "0.0.0.0", "--port", "9010"],
    )

    _wait_for_url("http://localhost:9009/.well-known/agent-card.json")
    _wait_for_url("http://localhost:9010/.well-known/agent-card.json")

    results: list[dict[str, object]] = []
    overall_start = time.monotonic()
    case_failures = False
    try:
        for case in cases:
            case_config = {
                "symbols": case.get("symbols", []),
                "settlement_date": case.get("settlement_date", ""),
                "finra_client_id": finra_client_id,
                "finra_client_secret": finra_client_secret,
            }
            result = asyncio.run(
                _run_case(
                    green_url="http://localhost:9009",
                    purple_url="http://purple:9010",
                    config=case_config,
                    http_timeout=args.http_timeout,
                    agent_id=agent_id,
                )
            )
            status = result.get("status")
            if status != "pass":
                case_failures = True
            results.append(
                {
                    "name": case.get("name", ""),
                    "status": status,
                    "duration_seconds": result.get("duration_seconds"),
                    "details": result.get("data"),
                }
            )
    finally:
        if case_failures:
            _dump_container_logs("green")
            _dump_container_logs("purple")
        _cleanup_container("purple")
        _cleanup_container("green")

    passed = sum(1 for item in results if item.get("status") == "pass")
    overall = "pass" if passed == len(results) else "fail"
    total_duration = round(time.monotonic() - overall_start, 3)
    avg_duration = round(total_duration / len(results), 3) if results else None
    created_at = datetime.utcnow().isoformat() + "Z"

    payload = {
        "id": purple_id or purple_image,
        "status": overall,
        "passed": passed,
        "total": len(results),
        "total_duration_seconds": total_duration,
        "average_duration_seconds": avg_duration,
        "results": results,
        "created_at": created_at,
        "green_agent_id": green_id,
        "purple_agent_id": purple_id or purple_image,
        "purple_image": purple_image,
        "config": {"cases": cases},
    }

    results_dir = Path(__file__).resolve().parents[1] / "results"
    _write_results(payload, results_dir)
    _post_results(payload)


if __name__ == "__main__":
    main()
