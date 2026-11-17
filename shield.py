"""Compatibilidad: el código vive en el paquete `llm_guardrails_shield`. Este módulo se
conserva para quien añade esta carpeta a `sys.path` e importa `shield`
directamente."""

from llm_guardrails_shield.shield import *  # noqa: F401,F403
from llm_guardrails_shield.shield import LLMGuardrailsShield  # noqa: F401
