"""Parameter introspection helpers for @framework_tool discovery.

Extracts per-parameter descriptions and type annotations from function
docstrings and signatures so the tool manifest's parameter schema is useful
to the secretary model instead of being generic placeholders like
``"description": "Parameter module_path"``.
"""

import inspect
import re
from typing import Any, Callable, Dict


def parse_param_docs(func: Callable) -> Dict[str, str]:
    """Parse per-parameter descriptions from a function's docstring.

    Supports Google-style (``Args:``) and NumPy-style (``Parameters``
    section) docstrings.  Returns a dict mapping parameter name to its
    description string.  Falls back to an empty dict when the docstring
    has no structured parameter docs.
    """
    doc = inspect.getdoc(func)
    if not doc:
        return {}

    result: Dict[str, str] = {}

    # Google-style: "Args:\n    name: description\n    name2: desc2"
    google_match = re.search(
        r"(?:Args|Arguments|Parameters)\s*:\s*\n((?:[ \t]+.+\n?)+)", doc
    )
    if google_match:
        block = google_match.group(1)
        for line in block.strip().splitlines():
            # Each line: "param_name: description" or "param_name (type): desc"
            # Leading whitespace is optional since .strip() may have removed it.
            m = re.match(r"\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*(.+)", line)
            if m:
                result[m.group(1)] = m.group(2).strip()
        if result:
            return result

    # NumPy-style: "Parameters\n----------\nname : type\n    description"
    numpy_match = re.search(
        r"Parameters\s*\n\s*-+\s*\n((?:.+\n?)+?)(?=\n\s*[A-Z][a-z]+\s*\n|\n\s*-+|\Z)",
        doc,
    )
    if numpy_match:
        block = numpy_match.group(1)
        current_name = None
        current_desc = ""
        for line in block.splitlines():
            # Parameter header: "name : type" or just "name"
            header = re.match(r"\s*(\w+)\s*(?::\s*\S+)?\s*$", line)
            if header:
                if current_name and current_desc:
                    result[current_name] = current_desc.strip()
                current_name = header.group(1)
                current_desc = ""
            elif line.startswith("    ") and current_name:
                current_desc += " " + line.strip()
        if current_name and current_desc:
            result[current_name] = current_desc.strip()
        if result:
            return result

    return result


def annotation_to_schema_type(annotation: Any) -> str:
    """Map a Python type annotation to a JSON Schema type string.

    Falls back to "string" for untyped parameters (no annotation or
    ``inspect.Parameter.empty``), which is the safe default since most
    tool arguments are strings.
    """
    if annotation is inspect.Parameter.empty:
        return "string"
    # Unwrap Optional[X], Union[X, None], etc.
    origin = getattr(annotation, "__origin__", None)
    if origin is not None:
        # Optional[X] -> Union[X, None], get the non-None type.
        args = getattr(annotation, "__args__", ())
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return annotation_to_schema_type(non_none[0])
        return "string"
    type_map = {
        int: "integer",
        float: "number",
        bool: "boolean",
        str: "string",
        list: "array",
        dict: "object",
        tuple: "array",
    }
    return type_map.get(annotation, "string")
