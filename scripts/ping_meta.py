"""Connectivity check for Meta Model API."""

from airlock.meta_client import ping


if __name__ == "__main__":
    print(ping())
