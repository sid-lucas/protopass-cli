import os
import sys


def _dispatch_internal_mode():
    """
    Internal helper used when the packaged binary relaunches itself to run
    auxiliary processes (agent/server). This keeps CLI args untouched for users.
    """
    mode = os.environ.get("PROTOPASS_INTERNAL_MODE")
    if mode == "agent":
        from client.agent.protopass_agent import main as agent_main
        sys.exit(agent_main() or 0)
    if mode == "server":
        from server.app import run_server
        sys.exit(run_server() or 0)
    return False


if __name__ == "__main__":
    handled = _dispatch_internal_mode()
    if not handled:
        from client.cli import main
        main()
