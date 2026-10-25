"""Potocus tools package."""

from src.tools.expert import (
    TOOL_NAME as CONSULT_TOOL_NAME,
    ConsultResult,
    SpecialistBudget,
    SpecialistBudgetExceeded,
    consult_security_expert,
    new_budget_from_config,
)
from src.tools.risk_classification import (
    ClassificationResult,
    RiskTier,
    classify_command,
    tier_requires_hitl,
)
from src.tools.discovery import (
    TOOL_NAME as SEARCH_TOOLS_NAME,
    index_tools,
    search_kali_tools,
)
from src.tools.terminal import (
    TOOL_NAME as EXECUTE_TOOL_NAME,
    ExecutionResult,
    execute_kali_command,
    parse_command,
)
from src.tools.filesystem import (
    build_filesystem_tools,
    read_file,
    write_file,
    create_file,
    edit_file,
    edit_file_lines,
    apply_patch,
    delete_file,
    list_directory,
    make_directory,
    move_file,
    copy_file,
    search_files,
    file_info,
)
from src.tools.web import (
    build_web_tools,
    web_search,
    fetch_url,
    get_cve_details,
)

__all__ = [
    "CONSULT_TOOL_NAME",
    "EXECUTE_TOOL_NAME",
    "SEARCH_TOOLS_NAME",
    "index_tools",
    "search_kali_tools",
    "ConsultResult",
    "SpecialistBudget",
    "SpecialistBudgetExceeded",
    "consult_security_expert",
    "new_budget_from_config",
    "ClassificationResult",
    "RiskTier",
    "classify_command",
    "tier_requires_hitl",
    "ExecutionResult",
    "execute_kali_command",
    "parse_command",
    "build_filesystem_tools",
    "read_file",
    "write_file",
    "create_file",
    "edit_file",
    "edit_file_lines",
    "apply_patch",
    "delete_file",
    "list_directory",
    "make_directory",
    "move_file",
    "copy_file",
    "search_files",
    "file_info",
    "build_web_tools",
    "web_search",
    "fetch_url",
    "get_cve_details",
]
