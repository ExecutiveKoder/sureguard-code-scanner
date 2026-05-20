"""MCP tool implementations.

Each module exposes one or more pure-async functions returning ScanResult /
PackageVerification. The MCP server wires them up; the same functions can be
called from tests or CLI without going through MCP transport.
"""
