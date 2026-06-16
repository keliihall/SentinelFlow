# example-echo

`example-echo` is a safe SentinelFlow example integration. It declares one low-risk
capability that echoes a caller-provided string.

P2-2 adds one small out-of-process Python runner. It reads a JSON object from stdin,
requires a string `message`, and writes a JSON object containing that same message.
The fixed runner accepts no command fragments or target arguments.

The plugin performs no scanning, networking, credential handling, persistence, or
system modification.
