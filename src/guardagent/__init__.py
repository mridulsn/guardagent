"""guardagent: a tool-using agent with a guard layer between the model and its tools."""


def main() -> int:
    from .cli import main as _main

    return _main()
