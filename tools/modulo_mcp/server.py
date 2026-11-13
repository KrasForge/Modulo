"""MCP tools for authenticated Modulo plugin-state entries."""
from __future__ import annotations

from typing import Any, Literal

try:
    from .client import ModuloClient
except ImportError:  # Direct stdio invocation from .mcp.json.
    from client import ModuloClient

from fastmcp import FastMCP

mcp = FastMCP("modulo-workspace")


@mcp.tool()
def list_installed_plugins() -> dict:
    """List account-recorded plugin installations and enabled status. Built-in defaults may be absent until saved."""
    return ModuloClient().installed_plugins()


@mcp.tool()
def list_plugin_records(plugin_id: str, cursor: str | None = None, limit: int = 100) -> dict:
    """Inspect a storage namespace, not necessarily its UI plugin ID. Life/PARA/Tasks is workspace-para, key data, value.tasks. Use nextCursor for the next page."""
    return ModuloClient().list_records(plugin_id, cursor, limit)


@mcp.tool()
def get_plugin_record(plugin_id: str, key: str) -> dict:
    """Read one plugin-state record, including its schema and version, before adding an entry."""
    return ModuloClient().get_record(plugin_id, key)


@mcp.tool()
def list_workspace_records(namespace: str, cursor: str | None = None, limit: int = 100) -> dict:
    """Read shared workspace data. Life/PARA/Tasks uses namespace='para', key='data', value.tasks. UI plugin IDs such as para-tasks do not own these records."""
    return ModuloClient().list_workspace_records(namespace, cursor, limit)


@mcp.tool()
def get_workspace_record(namespace: str, key: str = "data") -> dict:
    """Read shared workspace data, e.g. namespace='para' for Life/PARA tasks, projects, areas and resources. Includes schema and optimistic version."""
    return ModuloClient().get_workspace_record(namespace, key)


@mcp.tool()
def register_plugin_schema(plugin_id: str, schema_id: str, schema: dict[str, Any],
                           schema_version: int = 1) -> str:
    """Register an immutable custom schema in a plugin namespace before creating its first record."""
    ModuloClient().register_schema(plugin_id, schema_id, schema, schema_version)
    return "Schema registered"


@mcp.tool()
def create_plugin_record(plugin_id: str, key: str, schema_id: str, value: Any,
                         schema_version: int = 1) -> dict:
    """Create a native plugin-state record with an existing registered schema. Fails if the key exists."""
    return ModuloClient().create_record(plugin_id, key, schema_id, value, schema_version)


@mcp.tool()
def append_plugin_entry(plugin_id: str, key: str, array_path: str, entry: Any,
                        expected_version: int | None = None) -> dict:
    """Append to an existing plugin record's JSON array (e.g. /data/records); preserves schema and rejects concurrent changes."""
    return ModuloClient().append_entry(plugin_id, key, array_path, entry, expected_version)


@mcp.tool()
def update_para_task_status(task_id: str, status: Literal["Next", "Waiting", "Done"],
                            expected_version: int) -> dict:
    """Update exactly one Life/PARA task status. Read the workspace record first and pass its version; concurrent changes are rejected."""
    return ModuloClient().update_para_task_status(task_id, status, expected_version)


@mcp.tool()
def create_note(title: str, content: str = "", tags: list[str] | None = None) -> dict:
    """Create a native Notes plugin entry with Markdown content and optional tags."""
    return ModuloClient().create_note(title, content, tags)


@mcp.tool()
def cti_search(query: str | None = None, kind: str | None = None, view: str | None = None, limit: int = 25) -> dict:
    """Search the CTI knowledge base before deriving anything: 'what do we know about X?'. kind is one of actor, identity, infrastructure, malware, indicator, campaign, victim, lead, watch, enrichment, disclosure. view is a saved queue: live-c2, open-leads, stale-leads, unattributed-identities, expiring-indicators, unhealthy-watches, unnotified-victims. Defanged values (evil[.]com) match."""
    return ModuloClient().cti_search(query, kind, view, limit)


@mcp.tool()
def cti_get(object_id: str) -> dict:
    """Read one CTI record with all relationships (the far end summarized) and its change history."""
    return ModuloClient().cti_get(object_id)


@mcp.tool()
def cti_ingest(batch: dict[str, Any]) -> dict:
    """Record findings as CTI records. batch = {source, objects:[{ref, kind, name?, status?, tlp?, confidence?, attributes, labels?, firstSeen?, lastSeen?}], relationships:[{source, target, type}], watch?:{watchType, target, result}}. Endpoints are batch refs, record ids, or {kind, key} natural keys such as {"kind":"actor","key":"tronzitveca"} or {"kind":"identity","key":"handle:apollo1030109"}. Idempotent: re-sending changes nothing; lists are unioned and TLP is never lowered."""
    return ModuloClient().cti_ingest(batch)


@mcp.tool()
def cti_link(source_id: str, target_id: str, relationship_type: str, confidence: int | None = None,
             description: str | None = None) -> dict:
    """Link two existing CTI records with a typed STIX-style relationship such as attributed-to, alias-of, uses, communicates-with, resolves-to, rotation-of, hosts, drops, indicates, based-on, part-of, targets, concerns, enriches or related-to."""
    return ModuloClient().cti_link(source_id, target_id, relationship_type, confidence, description)


@mcp.tool()
def cti_changes(since: str | None = None, limit: int = 100) -> dict:
    """What changed in the CTI knowledge base since an ISO-8601 time."""
    return ModuloClient().cti_changes(since, limit)


@mcp.tool()
def cti_summary() -> dict:
    """CTI overview: counts per kind, live C2, open and stale leads, unattributed identities, unhealthy watches and recent changes."""
    return ModuloClient().cti_summary()


@mcp.tool()
def cti_graph(focus: str | None = None, depth: int = 2) -> dict:
    """The typed neighbourhood of a CTI record (or the recent overview) as nodes and edges."""
    return ModuloClient().cti_graph(focus, depth)


if __name__ == "__main__":
    mcp.run()
