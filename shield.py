import re
import logging
from typing import Tuple, Optional, List

logger = logging.getLogger(__name__)


class LLMGuardrailsShield:
    """
    Cortafuegos de seguridad bidireccional (Guardrails) para LLMs.
    
    Protege los flujos de inteligencia artificial interceptando la entrada
    (bloqueo de inyecciones de prompt, anonimizacion de PII, filtrado de toxicidad)
    y la salida (evitar fugas de claves/secretos y verificar alineacion con el contexto RAG).
    """

    def __init__(
        self,
        toxic_keywords: Optional[List[str]] = None,
        redact_placeholder_email: str = "[EMAIL]",
        redact_placeholder_phone: str = "[PHONE]"
    ) -> None:
        self.redact_email_tpl = redact_placeholder_email
        self.redact_phone_tpl = redact_placeholder_phone
        
        # Diccionario local basico de terminos toxicos/ofensivos
        self.toxic_words = toxic_keywords or [
            "insulto1", "insulto2", "ofensa1", "ofensa2",
            "mierda", "cabron", "gilipollas", "puta"
        ]
        
        # Expresiones regulares para PII (Personally Identifiable Information)
        self.email_regex = re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"
        )
        # Soporta formatos telefonicos comunes espanoles e internacionales (+34..., 600...)
        self.phone_regex = re.compile(
            r"\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,3}\)?[-.\s]?\d{3}[-.\s]?\d{3,4}\b"
        )
        
        # Expresiones para deteccion de Prompt Injections y jailbreaks comunes
        self.injection_patterns = [
            re.compile(r"\bignore\b.*\b(all|previous|instructions)\b", re.IGNORECASE),
            re.compile(r"\bsystem\s+prompt\b.*\b(override|expose|reveal|bypass|reveal)\b", re.IGNORECASE),
            re.compile(r"\b(reveal|expose|override|bypass|show)\b.*\bsystem\s+prompt\b", re.IGNORECASE),
            re.compile(r"\berase\b.*\b(system|previous)\b.*\binstructions\b", re.IGNORECASE),
            re.compile(r"\byou\s+are\s+now\s+an\s+unrestricted\b", re.IGNORECASE),
            re.compile(r"\bdan\s+mode\b", re.IGNORECASE),
            re.compile(r"\[\s*system\s*:\s*override\s*\]", re.IGNORECASE)
        ]
        
        # Expresiones para detectar fugas en la salida (Secretos, API Keys)
        self.secret_leakage_patterns = [
            re.compile(r"\b(sk-[a-zA-Z0-9_-]{20,})\b"),  # OpenAI API Keys clasicas y sk-proj-
            re.compile(r"\b(AIzaSy[a-zA-Z0-9-_]{33})\b"),  # Google API Keys
            re.compile(r"\b(password|contraseña|apikey|secret_key)\s*[:=]\s*[a-zA-Z0-9_-]{8,}\b", re.IGNORECASE)
        ]

    def redact_pii(self, text: str) -> str:
        """
        Detecta informacion de identificacion personal (PII) en el texto
        y la reemplaza por placeholders seguros.
        """
        temp = self.email_regex.sub(self.redact_email_tpl, text)
        return self.phone_regex.sub(self.redact_phone_tpl, temp)

    def validate_input(self, prompt: str) -> Tuple[bool, str, str]:
        """
        Analiza un prompt de entrada aplicando politicas de seguridad.
        
        Returns:
            Tupla (is_safe: bool, processed_prompt: str, block_reason: str)
        """
        # 1. Comprobar Prompt Injection
        for pattern in self.injection_patterns:
            if pattern.search(prompt):
                logger.warning(f"Intento de inyeccion bloqueado: {pattern.pattern}")
                return False, "", "Entrada bloqueada por sospecha de Prompt Injection / Jailbreak."
                
        # 2. Comprobar Toxicidad / Ofensas
        prompt_lower = prompt.lower()
        for toxic in self.toxic_words:
            if re.search(rf"\b{re.escape(toxic)}\b", prompt_lower):
                logger.warning(f"Contenido ofensivo detectado en la entrada: {toxic}")
                return False, "", "Entrada bloqueada debido a lenguaje ofensivo o inapropiado."
                
        # 3. Anonimizar PII
        clean_prompt = self.redact_pii(prompt)
        
        return True, clean_prompt, ""

    def validate_output(self, generation: str, context: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Valida la respuesta del modelo antes de retornarla al cliente.
        Evita fugas de claves de API o alucinaciones flagrantes frente al contexto.
        
        Returns:
            Tupla (is_safe: bool, processed_output: str, block_reason: str)
        """
        # 1. Comprobar fugas de API Keys o Secretos
        for pattern in self.secret_leakage_patterns:
            if pattern.search(generation):
                logger.error(f"Intento de fuga de secreto bloqueado: {pattern.pattern}")
                return False, "", "Salida bloqueada debido a deteccion de fuga de informacion confidencial (API Keys/Credenciales)."
                
        # 2. Comprobar alineacion factica con el contexto (Hallucination Guardrail para RAG)
        if context is not None:
            # Si el contexto no es vacio y la respuesta es sustancial, calculamos solapamiento de terminos
            gen_words = set(re.findall(r"\b\w{4,}\b", generation.lower()))
            ctx_words = set(re.findall(r"\b\w{4,}\b", context.lower()))
            
            if gen_words:
                overlap = gen_words.intersection(ctx_words)
                ratio = len(overlap) / len(gen_words)
                
                # Si menos del 15% de los conceptos de la respuesta provienen del contexto original,
                # se asume que el modelo esta alucinando (inventando hechos no suministrados).
                if ratio < 0.15:
                    logger.warning(f"Hallucinacion detectada. Similitud factica: {ratio:.2f}")
                    return False, "", "Salida bloqueada debido a falta de consistencia factica con los documentos fuente (Alucinacion)."
                    
        return True, generation, ""
