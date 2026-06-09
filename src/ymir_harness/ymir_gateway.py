from __future__ import annotations

import os

from ymir_harness.enforcement import enforce_benchmark_boundaries


def main() -> None:
    from ymir.tools.privileged.gateway import main as gateway_main  # type: ignore[import-not-found]

    with enforce_benchmark_boundaries(os.environ):
        gateway_main()


if __name__ == "__main__":
    main()
