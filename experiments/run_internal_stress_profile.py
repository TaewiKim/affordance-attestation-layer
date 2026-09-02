#!/usr/bin/env python3
"""Compatibility entry point for the author-developed implementation stress profile.

The underlying historical module name is retained to preserve result hashes and
artifact paths; this public entry point avoids describing it as an independent
red team. AgentDojo is the external penetration benchmark.
"""
from run_red_team_profile import main


if __name__ == "__main__":
    main()
