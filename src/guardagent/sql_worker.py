"""One disposable SQL process per request; never imports or calls a provider."""
import json
import resource
import sys
from pathlib import Path

from .tools import DbError, SqlExecutor


def main():
    request = json.load(sys.stdin)
    # Linux enforces an address-space ceiling as well as SQLite's heap cap.
    # macOS does not reliably enforce RLIMIT_AS; SQLite allocations are bounded
    # there by hard_heap_limit in this isolated process instead.
    if sys.platform.startswith("linux"):
        resource.setrlimit(resource.RLIMIT_AS, (512 * 1024 * 1024, 512 * 1024 * 1024))
    seconds = max(1, int(request["max_seconds"]) + 1)
    resource.setrlimit(resource.RLIMIT_CPU, (seconds, seconds + 1))
    try:
        executor = SqlExecutor(Path(request["db_path"]), request["max_vm_steps"],
                               request["max_seconds"], request["max_value_bytes"])
        reply = {"result": executor._run_local(request["sql"], request["max_rows"])}
    except DbError as exc:
        reply = {"error": {"rule": exc.rule, "detail": exc.detail}}
    except MemoryError:
        reply = {"error": {"rule": "db.too_large", "detail": "query exceeded its memory budget"}}
    print(json.dumps(reply, ensure_ascii=True))


if __name__ == "__main__":
    main()
