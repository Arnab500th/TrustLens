# backend/scripts/check_module.py
# Checks a teammate's file BEFORE you copy it into place.
# usage (from the backend folder):  python -m scripts.check_module incoming/url.py [https://example.com/]
import asyncio
import importlib.util
import inspect
import os
import re
import sys
import time

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BACKEND)

from core.models import ModuleResult, ScanContext

IDS_PATH = os.path.join(BACKEND, "docs", "finding_ids.txt")
VALID_NAMES = {"url", "domain", "certificate", "headers", "reputation", "page"}
FORBIDDEN = ("playwright", "selenium", "pyppeteer")      # we never run a site's scripts
LIMIT_SECONDS = 15


def load_master_ids():
    with open(IDS_PATH, encoding="utf-8") as fh:
        return set(fh.read().split())


def load(path):
    spec = importlib.util.spec_from_file_location("candidate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_ctx(url):
    from core.context import build_context
    return build_context(url)


def check_file(path, url="https://example.com/"):
    """Returns (problems, warnings, result_or_None). No problems means PASS."""
    problems, warnings, res = [], [], None
    name = os.path.splitext(os.path.basename(path))[0]
    try:
        source = open(path, encoding="utf-8").read()
    except OSError as e:
        return [f"cannot read file: {e}"], warnings, None

    # static checks
    if name not in VALID_NAMES:
        warnings.append(f"file name '{name}' is not one of {sorted(VALID_NAMES)}")
    for bad in FORBIDDEN:
        if re.search(rf"^\s*(import|from)\s+{bad}\b", source, re.M):
            problems.append(f"uses {bad}, but we must never run a website's scripts")
    if '__name__ == "__main__"' not in source and "__name__ == '__main__'" not in source:
        warnings.append("no self-check block at the end of the file (rule B7)")

    # import
    try:
        mod = load(path)
    except Exception as e:
        return problems + [f"cannot import the file: {e!r}"], warnings, None
    run = getattr(mod, "run", None)
    if run is None:
        return problems + ["no function named run"], warnings, None
    if not inspect.iscoroutinefunction(run):
        return problems + ["run must be 'async def run(ctx)'"], warnings, None

    # call it
    try:
        ctx = make_ctx(url)
    except Exception as e:
        return problems + [f"could not build the test context: {e!r}"], warnings, None
    start = time.monotonic()
    try:
        res = asyncio.run(asyncio.wait_for(run(ctx), LIMIT_SECONDS))
    except asyncio.TimeoutError:
        return problems + [f"took longer than {LIMIT_SECONDS} seconds"], warnings, None
    except Exception as e:
        return problems + [f"run() raised an error instead of returning a result: {e!r}"], warnings, None
    took = time.monotonic() - start

    # check the result
    if not isinstance(res, ModuleResult):
        return problems + ["run() did not return a ModuleResult"], warnings, None
    if res.module != name and name in VALID_NAMES:
        problems.append(f"result.module is '{res.module}' but the file is '{name}'")
    if res.status == "failed":
        warnings.append(f"status is failed: {res.error} (no internet or a real bug? run it again)")
    if res.status == "skipped":
        warnings.append("status is skipped: nothing was checked")
    if not isinstance(res.facts, dict):
        problems.append("facts must be a dict")
    master = load_master_ids()
    for f in res.findings:
        if f.id not in master:
            problems.append(f"unknown finding id {f.id} (not in docs/finding_ids.txt)")
        if not f.description.strip():
            problems.append(f"empty description on {f.id}")
        if f.points < 0 or f.points > 100:
            problems.append(f"points out of range on {f.id}: {f.points}")
        if f.source != name and name in VALID_NAMES:
            warnings.append(f"finding {f.id} has source '{f.source}', expected '{name}'")
    if took > 10:
        warnings.append(f"slow: {took:.1f} seconds")
    return problems, warnings, res


if __name__ == "__main__" and len(sys.argv) > 1:
    p, w, r = check_file(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "https://example.com/")
    if r is not None:
        print(f"module={r.module} status={r.status} facts={list(r.facts)} "
              f"findings={[(f.id, f.points) for f in r.findings]}")
    for x in w:
        print("WARN:", x)
    print("PASS" if not p else "FAIL: " + "; ".join(p))
    sys.exit(1 if p else 0)

elif __name__ == "__main__":
    # self-check: write one good and three bad files, check each
    import tempfile
    GOOD = ('from core.models import ModuleResult, Finding\n'
            'async def run(ctx):\n'
            '    return ModuleResult(module="url", findings=[Finding(id="LONG_URL", source="url", description="long", points=5)])\n'
            'if __name__ == "__main__":\n    pass\n')
    BAD_ID = GOOD.replace("LONG_URL", "MADE_UP_ID")
    RAISES = 'async def run(ctx):\n    raise RuntimeError("x")\n'
    NOT_ASYNC = 'def run(ctx):\n    return None\n'
    with tempfile.TemporaryDirectory() as d:
        cases = [("good", GOOD, True), ("bad id", BAD_ID, False),
                 ("raises", RAISES, False), ("not async", NOT_ASYNC, False)]
        ok = True
        for label, code, should_pass in cases:
            path = os.path.join(d, "url.py")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(code)
            problems, _, _ = check_file(path)
            passed = not problems
            good = passed == should_pass
            ok = ok and good
            print(f"{label:10} -> {'passed' if passed else 'rejected'}  {'OK' if good else 'WRONG'}")
    print("PASS" if ok else "FAIL")