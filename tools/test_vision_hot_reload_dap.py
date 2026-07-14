#!/usr/bin/env python3
"""Small protocol smoke test for Vision's netcoredbg DAP extension."""

import json
import subprocess
import sys


def write_message(process, sequence, command, arguments):
    payload = json.dumps(
        {"seq": sequence, "type": "request", "command": command, "arguments": arguments},
        separators=(",", ":"),
    ).encode("utf-8")
    process.stdin.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
    process.stdin.write(payload)
    process.stdin.flush()


def read_message(process):
    content_length = None
    while True:
        line = process.stdout.readline()
        if not line:
            raise RuntimeError("debug adapter closed its output stream")
        if line == b"\r\n":
            break
        name, value = line.decode("ascii").split(":", 1)
        if name.lower() == "content-length":
            content_length = int(value.strip())
    if content_length is None:
        raise RuntimeError("DAP response did not include Content-Length")
    return json.loads(process.stdout.read(content_length))


def read_response(process, request_sequence):
    while True:
        message = read_message(process)
        if message.get("type") == "response" and message.get("request_seq") == request_sequence:
            return message


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: test_vision_hot_reload_dap.py <netcoredbg>")

    process = subprocess.Popen(
        [sys.argv[1], "--interpreter=vscode"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        write_message(
            process,
            1,
            "initialize",
            {
                "adapterID": "coreclr",
                "clientID": "vision-fork-test",
                "linesStartAt1": True,
                "columnsStartAt1": True,
                "pathFormat": "path",
            },
        )
        initialize = read_response(process, 1)
        assert initialize["success"] is True, initialize
        capabilities = initialize["body"]
        assert capabilities.get("supportsVisionHotReload") is True, capabilities
        assert capabilities.get("visionHotReloadProtocolVersion") == 1, capabilities

        write_message(process, 2, "visionApplyHotReload", {"protocolVersion": 1})
        malformed = read_response(process, 2)
        assert malformed["success"] is False, malformed
        assert malformed["body"]["visionErrorCode"] == "vision_hot_reload_invalid_request", malformed
    finally:
        process.kill()
        process.wait(timeout=10)


if __name__ == "__main__":
    main()
