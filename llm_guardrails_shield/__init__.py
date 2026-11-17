"""Bidirectional LLM firewall: prompt-injection, toxicity and secret-leak detection."""

from .shield import LLMGuardrailsShield

__version__ = "0.1.0"

__all__ = ['LLMGuardrailsShield']
