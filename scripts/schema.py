"""A GraphQL schema's operations, as JSON, for ./operations.sh.

    python3 scripts/schema.py schema.graphql

Every field of the schema's mutation and subscription types -- each an
operation a request can hold -- with its description, whether it is
deprecated and why, and its category: GitHub's @docsCategory, the grouping
its documentation uses, and the one its REST description calls
x-github.category. Queries are not listed: a query is a read, whatever it
reads, and is one operation of its own.

Read with graphql-core, the reference reader's port, so a schema is read as
GraphQL rather than as lines: the dev shell has it.
"""

import json
import sys

from graphql import parse
from graphql.language import (
    ObjectTypeDefinitionNode,
    ObjectTypeExtensionNode,
    SchemaDefinitionNode,
)


def string_argument(directive, name):
    for argument in directive.arguments:
        if argument.name.value == name:
            return argument.value.value
    return None


def main(path):
    with open(path, encoding="utf-8") as f:
        document = parse(f.read(), no_location=True)

    # The root types are Mutation and Subscription unless a schema
    # definition names others.
    roots = {"mutation": "Mutation", "subscription": "Subscription"}
    for definition in document.definitions:
        if isinstance(definition, SchemaDefinitionNode):
            for operation in definition.operation_types:
                roots[operation.operation.value] = operation.type.name.value

    out = {kind: [] for kind in roots}
    for definition in document.definitions:
        if not isinstance(definition, (ObjectTypeDefinitionNode, ObjectTypeExtensionNode)):
            continue
        for kind, root in roots.items():
            if definition.name.value != root:
                continue
            for field in definition.fields:
                directives = {d.name.value: d for d in field.directives}
                entry = {
                    "name": field.name.value,
                    "description": field.description.value if field.description else None,
                    "category": None,
                    "deprecated": None,
                }
                if "docsCategory" in directives:
                    entry["category"] = string_argument(directives["docsCategory"], "name")
                if "deprecated" in directives:
                    entry["deprecated"] = string_argument(directives["deprecated"], "reason") or "Deprecated."
                out[kind].append(entry)
    json.dump(out, sys.stdout, indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
