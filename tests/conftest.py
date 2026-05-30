"""Shared test fixtures."""
import sys
import os

# Add src to path so tests can import ethernetip
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
