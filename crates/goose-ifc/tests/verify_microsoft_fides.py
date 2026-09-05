import argparse
import ast
import asyncio
import importlib
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace


def verify_source(upstream, fixtures):
    commit = subprocess.check_output(
        ["git", "-C", str(upstream), "rev-parse", "HEAD"], text=True
    ).strip()
    if commit != fixtures["upstream"]["commit"]:
        raise RuntimeError(f"Expected {fixtures['upstream']['commit']}, found {commit}")
    subprocess.run(
        ["git", "-C", str(upstream), "diff", "--exit-code", "HEAD", "--", "python/packages/core"],
        check=True,
    )
    tree = ast.parse((upstream / fixtures["upstream"]["test_file"]).read_text())
    tests = set()
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            tests.add(node.name)
            tests.update(
                f"{node.name}.{method.name}"
                for method in node.body
                if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
    for group in ("label_cases", "result_cases", "annotation_cases", "policy_cases"):
        for case in fixtures[group]:
            if case["upstream_test"] not in tests:
                raise RuntimeError(f"Unknown upstream test: {case['upstream_test']}")
    core = upstream / "python/packages/core"
    sys.path.insert(0, str(core))
    api = importlib.import_module("agent_framework")
    security = importlib.import_module("agent_framework.security")
    if Path(security.__file__).resolve() != core / "agent_framework/security.py":
        raise RuntimeError("Imported security module is not from the pinned checkout")
    return api, security


def read_label(security, fixtures, name):
    return security.ContentLabel.from_dict(fixtures["labels"][name])


def check(actual, expected, case):
    if actual != expected:
        raise AssertionError(f"{case['id']}: expected {expected!r}, got {actual!r}")


def run_label_case(security, fixtures, case):
    inputs = [read_label(security, fixtures, name) for name in case["inputs"]]
    if case["operation"] == "join":
        actual = security.combine_labels(*inputs)
    elif case["operation"] == "roundtrip":
        actual = inputs[0]
    else:
        raise RuntimeError(f"Unknown operation: {case['operation']}")
    check(actual.to_dict(), fixtures["labels"][case["expected"]], case)


async def fixture_tool() -> str:
    return "fixture"


async def run_result_case(api, security, fixtures, case):
    fallback = fixtures["labels"][case["fallback"]]
    function = api.FunctionTool(
        fn=fixture_tool,
        name="fixture",
        description="Compatibility fixture",
        additional_properties={
            "source_integrity": fallback["integrity"],
            "confidentiality": fallback["confidentiality"],
        },
    )
    context = api.FunctionInvocationContext(function=function, arguments={})
    tracker = security.LabelTrackingFunctionMiddleware(auto_hide_untrusted=case["auto_hide"])
    tracker._context_label = read_label(security, fixtures, case["initial"])

    async def return_items():
        context.result = []
        for item in case["items"]:
            metadata = dict(item.get("metadata", {}))
            if "label" in item:
                metadata["security_label"] = fixtures["labels"][item["label"]]
            context.result.append(
                api.Content.from_text(item["text"], additional_properties=metadata)
            )

    await tracker.process(context, return_items)
    check(tracker._context_label.to_dict(), fixtures["labels"][case["context"]], case)
    check(len(context.result), len(case["items"]), case)
    for index, content in enumerate(context.result):
        item = case["items"][index]
        metadata = content.additional_properties
        hidden = bool(metadata.get("_variable_reference"))
        check(hidden, case["hidden"][index], case)
        actual_label = dict(metadata["security_label"])
        if "label" not in item:
            actual_label.pop("metadata", None)
        check(actual_label, fixtures["labels"][case["expected_labels"][index]], case)
        if hidden:
            if item["text"] in content.text:
                raise AssertionError(f"{case['id']}: hidden body was returned")
        else:
            check(content.text, item["text"], case)
            for key, value in item.get("metadata", {}).items():
                check(metadata[key], value, case)


def run_annotation_case(security, case):
    annotations = (
        SimpleNamespace(**case["annotations"])
        if case["annotations"] is not None
        else None
    )
    integrity, maximum, accepts_untrusted = security._map_mcp_annotations_to_labels(annotations)
    check(integrity.value, case["integrity"], case)
    check(maximum.value if maximum is not None else None, case["maximum"], case)
    check(accepts_untrusted, case["accepts_untrusted"], case)


async def run_policy_case(api, security, fixtures, case):
    properties = {"accepts_untrusted": case["accepts_untrusted"]}
    if case["maximum"] is not None:
        properties["max_allowed_confidentiality"] = case["maximum"]
    function = api.FunctionTool(
        fn=fixture_tool,
        name="fixture",
        description="Compatibility fixture",
        additional_properties=properties,
    )
    context = api.FunctionInvocationContext(function=function, arguments={})
    context.metadata["context_label"] = read_label(security, fixtures, case["label"])
    policy = security.PolicyEnforcementFunctionMiddleware(block_on_violation=case["block"])
    called = False

    async def execute():
        nonlocal called
        called = True

    try:
        await policy.process(context, execute)
    except security.MiddlewareTermination:
        check(case["blocked"], True, case)
    check(not called, case["blocked"], case)


async def main():
    parser = argparse.ArgumentParser(
        description="Check shared FIDES fixtures against Microsoft's pinned source"
    )
    parser.add_argument(
        "upstream", type=Path, help="Clean checkout of the pinned Microsoft repository"
    )
    args = parser.parse_args()
    fixtures = json.loads((Path(__file__).parent / "fixtures/microsoft_fides.json").read_text())
    api, security = verify_source(args.upstream.resolve(), fixtures)
    for case in fixtures["label_cases"]:
        run_label_case(security, fixtures, case)
    for case in fixtures["result_cases"]:
        await run_result_case(api, security, fixtures, case)
    for case in fixtures["annotation_cases"]:
        run_annotation_case(security, case)
    for case in fixtures["policy_cases"]:
        await run_policy_case(api, security, fixtures, case)
    count = sum(
        len(fixtures[group])
        for group in ("label_cases", "result_cases", "annotation_cases", "policy_cases")
    )
    print(f"{count} shared cases passed against Microsoft {fixtures['upstream']['commit']}")


if __name__ == "__main__":
    asyncio.run(main())
