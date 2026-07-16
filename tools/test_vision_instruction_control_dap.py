#!/usr/bin/env python3
"""Exercise Vision's instruction-control extension against a real debuggee."""

import json
import os
import queue
import subprocess
import sys
import threading
import time


class DapClient:
    def __init__(self, adapter):
        self.process = subprocess.Popen(
            [adapter, "--interpreter=vscode"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.messages = queue.Queue()
        self.sequence = 0
        self.deferred = []
        self.reader = threading.Thread(target=self._read_messages, daemon=True)
        self.reader.start()

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=10)

    def request(self, command, arguments=None, timeout=30):
        self.sequence += 1
        request_sequence = self.sequence
        payload = json.dumps(
            {
                "seq": request_sequence,
                "type": "request",
                "command": command,
                "arguments": arguments or {},
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.process.stdin.write(f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii"))
        self.process.stdin.write(payload)
        self.process.stdin.flush()
        return self.wait_for(
            lambda message: message.get("type") == "response"
            and message.get("request_seq") == request_sequence,
            timeout,
        )

    def wait_for_event(self, event, timeout=30):
        return self.wait_for(
            lambda message: message.get("type") == "event" and message.get("event") == event,
            timeout,
        )

    def wait_for(self, predicate, timeout):
        for index, message in enumerate(self.deferred):
            if predicate(message):
                return self.deferred.pop(index)

        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                stderr = self.process.stderr.read().decode("utf-8", errors="replace")
                raise TimeoutError(f"DAP message timed out. stderr: {stderr}")
            message = self.messages.get(timeout=remaining)
            if isinstance(message, Exception):
                raise message
            if predicate(message):
                return message
            self.deferred.append(message)

    def _read_messages(self):
        try:
            while True:
                content_length = None
                while True:
                    line = self.process.stdout.readline()
                    if not line:
                        raise RuntimeError("debug adapter closed its output stream")
                    if line == b"\r\n":
                        break
                    name, value = line.decode("ascii").split(":", 1)
                    if name.lower() == "content-length":
                        content_length = int(value.strip())
                if content_length is None:
                    raise RuntimeError("DAP response did not include Content-Length")
                self.messages.put(json.loads(self.process.stdout.read(content_length)))
        except Exception as error:
            self.messages.put(error)


def marker_line(source_file, marker):
    with open(source_file, encoding="utf-8") as source:
        for number, line in enumerate(source, start=1):
            if marker in line:
                return number
    raise AssertionError(f"marker not found: {marker}")


def assert_success(response):
    assert response.get("success") is True, response
    return response.get("body") or {}


def main():
    if len(sys.argv) != 4:
        raise SystemExit(
            "usage: test_vision_instruction_control_dap.py <netcoredbg> <fixture.dll> <Program.cs>"
        )

    adapter = os.path.abspath(sys.argv[1])
    program = os.path.abspath(sys.argv[2])
    source_file = os.path.abspath(sys.argv[3])
    rewind_line = marker_line(source_file, "VISION_REWIND_TARGET")
    guard_line = marker_line(source_file, "VISION_GUARD_BREAKPOINT")
    outside_eh_line = marker_line(source_file, "VISION_EH_OUTSIDE_TARGET")
    eh_guard_line = marker_line(source_file, "VISION_EH_GUARD")

    client = DapClient(adapter)
    try:
        capabilities = assert_success(
            client.request(
                "initialize",
                {
                    "adapterID": "coreclr",
                    "clientID": "vision-instruction-control-test",
                    "linesStartAt1": True,
                    "columnsStartAt1": True,
                    "pathFormat": "path",
                },
            )
        )
        assert capabilities.get("supportsVisionInstructionPointerControl") is True, capabilities
        assert capabilities.get("visionInstructionPointerProtocolVersion") == 1, capabilities

        assert_success(
            client.request(
                "launch",
                {
                    "name": "Vision instruction-control fixture",
                    "type": "coreclr",
                    "request": "launch",
                    "program": program,
                    "cwd": os.path.dirname(program),
                    "stopAtEntry": False,
                    "justMyCode": False,
                },
            )
        )
        client.wait_for_event("initialized")
        breakpoints = assert_success(
            client.request(
                "setBreakpoints",
                {
                    "source": {"path": source_file},
                    "breakpoints": [{"line": guard_line}, {"line": eh_guard_line}],
                    "sourceModified": False,
                },
            )
        )
        assert breakpoints["breakpoints"][0]["id"] > 0, breakpoints
        assert_success(client.request("configurationDone"))

        first_stop = client.wait_for_event("stopped")
        thread_id = first_stop["body"]["threadId"]
        first_stack = assert_success(
            client.request("stackTrace", {"threadId": thread_id, "startFrame": 0, "levels": 10})
        )
        frame = first_stack["stackFrames"][0]
        assert frame["line"] == guard_line, first_stack

        resolved = assert_success(
            client.request(
                "visionResolveRewindTarget",
                {
                    "protocolVersion": 1,
                    "threadId": thread_id,
                    "frameId": frame["id"],
                    "sourceFile": source_file,
                    "line": rewind_line,
                },
            )
        )
        assert resolved["status"] == "safe", resolved
        assert resolved["targetId"], resolved
        assert resolved["targetIlOffset"] < resolved["frameIdentity"]["ilOffset"], resolved

        stale_target = assert_success(
            client.request(
                "visionResolveRewindTarget",
                {
                    "protocolVersion": 1,
                    "threadId": thread_id,
                    "frameId": frame["id"],
                    "sourceFile": source_file,
                    "line": rewind_line,
                },
            )
        )
        assert stale_target["status"] == "safe", stale_target

        moved = assert_success(
            client.request(
                "visionSetInstructionPointer",
                {
                    "protocolVersion": 1,
                    "rewindTargetId": resolved["targetId"],
                    "expectedFrameIdentity": resolved["frameIdentity"],
                },
            )
        )
        assert moved["moved"] is True, moved
        assert moved["handlesInvalidated"] is True, moved
        assert moved["stoppedFrame"]["line"] == rewind_line, moved

        stale_frame = client.request("scopes", {"frameId": frame["id"]})
        assert stale_frame.get("success") is False, stale_frame

        invalidated_target = client.request(
            "visionSetInstructionPointer",
            {
                "protocolVersion": 1,
                "rewindTargetId": stale_target["targetId"],
                "expectedFrameIdentity": stale_target["frameIdentity"],
            },
        )
        assert invalidated_target.get("success") is False, invalidated_target
        assert (
            invalidated_target["body"]["visionErrorCode"] == "rewind_target_not_found"
        ), invalidated_target

        second_target = assert_success(
            client.request(
                "visionResolveRewindTarget",
                {
                    "protocolVersion": 1,
                    "threadId": thread_id,
                    "frameId": moved["stoppedFrame"]["id"],
                    "sourceFile": source_file,
                    "line": rewind_line,
                },
            )
        )
        assert second_target["status"] == "unsafe", second_target
        assert second_target["reasonCode"] == "rewind_noop", second_target

        assert_success(client.request("continue", {"threadId": thread_id}))
        second_stop = client.wait_for_event("stopped")
        second_thread_id = second_stop["body"]["threadId"]
        second_stack = assert_success(
            client.request(
                "stackTrace",
                {"threadId": second_thread_id, "startFrame": 0, "levels": 10},
            )
        )
        assert second_stack["stackFrames"][0]["line"] == guard_line, second_stack

        assert_success(client.request("continue", {"threadId": second_thread_id}))
        eh_stop = client.wait_for_event("stopped")
        eh_thread_id = eh_stop["body"]["threadId"]
        eh_stack = assert_success(
            client.request(
                "stackTrace",
                {"threadId": eh_thread_id, "startFrame": 0, "levels": 10},
            )
        )
        eh_frame = eh_stack["stackFrames"][0]
        assert eh_frame["line"] == eh_guard_line, eh_stack
        unsafe_eh_target = assert_success(
            client.request(
                "visionResolveRewindTarget",
                {
                    "protocolVersion": 1,
                    "threadId": eh_thread_id,
                    "frameId": eh_frame["id"],
                    "sourceFile": source_file,
                    "line": outside_eh_line,
                },
            )
        )
        assert unsafe_eh_target["status"] == "unsafe", unsafe_eh_target
        assert unsafe_eh_target["reasonCode"] in (
            "exception_region_transition",
            "runtime_rejected_target",
        ), unsafe_eh_target
        assert_success(client.request("disconnect", {"terminateDebuggee": True}))
    finally:
        client.close()


if __name__ == "__main__":
    main()
