"""Loaded by pytest before collection so legacy tests cannot contact providers."""
from scripts.security_isolation.safety import guard, block_external_network

guard()
block_external_network()
