import re
import logging
from typing import Tuple, Optional, List

logger = logging.getLogger(__name__)

INJECTION_RULES = [
    # Ignorar / olvidar / anular las instrucciones previas
    r"\b(ignore|disregard|forget|skip|override)\b[^.\n]{0,40}\b(all|any|every|previous|prior|above|earlier|preceding|former)\b[^.\n]{0,30}\b(instructions?|prompts?|rules?|guidelines?|directions?|tasks?|context|conversation)\b",
    r"\bforget\s+(everything|all\s+(of\s+)?(that|this|the\s+above)|what\s+(i|we)\s+(said|told|talked))",
    r"\bignor(a|e|ar)\b[^.\n]{0,40}\b(instrucciones|indicaciones|reglas|ordenes|órdenes)\b",
    r"\b(olvida|olvidate|olvídate|olvida)\b[^.\n]{0,30}\b(todo|instrucciones|anterior|anteriores|lo\s+que)\b",
    r"\b(ignoriere|vergiss|vergessen\s+sie)\b[^.\n]{0,40}\b(alles|anweisungen|vorherigen|bisherigen|obigen|vorher|zuvor)\b",
    r"\bvergiss\s+alles\b",
    # Revelar o sustituir el prompt del sistema
    r"\b(reveal|expose|override|bypass|show|print|repeat|output|leak|display|spell[- ]?check)\b[^\n]{0,40}\b(system\s+prompt|initial\s+prompt|above\s+prompt|hidden\s+prompt|your\s+instructions|the\s+prompt\s+above)\b",
    r"\bsystem\s+prompt\b.*\b(override|expose|reveal|bypass)\b",
    r"\b(muestra|revela|imprime|repite)\b[^\n]{0,40}\b(prompt|instrucciones)\s+(del\s+sistema|iniciales|ocultas)\b",
    r"\b(zeige|gib|drucke|wiederhole)\b[^\n]{0,40}\b(prompt|anweisungen)\b",
    r"\berase\b.*\b(system|previous)\b.*\binstructions\b",
    # Nuevas instrucciones / cambio de rol forzado
    r"\b(new|neue|nueva|nuevas)\s+(instructions?|tasks?|aufgaben?|anweisungen|instrucciones|tareas?)\b\s*[:!]",
    r"\bnow\s+(you\s+are|act\s+as|pretend|respond\s+only|your\s+(new\s+)?task)\b",
    r"\b(jetzt|nun)\s+(bist\s+du|du\s+bist|tu\s+so\s+als)\b",
    r"\b(ahora|a\s+partir\s+de\s+ahora)\s+(eres|eres\s+un|act[uú]a\s+como|finge)\b",
    r"\byou\s+are\s+now\s+(an?\s+)?(unrestricted|unfiltered|jailbroken|evil|dan)\b",
    r"\b(dan|developer)\s+mode\b",
    r"\bjailbreak\b",
    r"\[\s*system\s*:\s*override\s*\]",
    r"={4,}\s*end\b",
    r"\b(do\s+anything\s+now|without\s+any\s+(restrictions|filters|limitations))\b",
]

DESTRUCTIVE_RULES = [
    r"\b(borra|elimina|destruye|delete|drop|remove)\b.*\b(base\s+de\s+datos|database|db|tabla|table)\b",
]


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
        redact_placeholder_phone: str = "[PHONE]",
        injection_detector: str = "hybrid",
        injection_threshold: Optional[float] = None,
        block_destructive: bool = True,
    ) -> None:
        """
        Args:
            injection_detector: ``rules`` (solo patrones), ``classifier`` (solo el modelo
                aprendido) o ``hybrid`` (bloquea si cualquiera de los dos lo detecta).
            injection_threshold: probabilidad a partir de la cual el clasificador bloquea
                (por defecto, la elegida por validacion cruzada; ver ``injection.py``).
            block_destructive: bloquear tambien peticiones de borrar bases de datos o tablas.
        """
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
        
        # Reglas de inyeccion: patrones de alta precision en ingles, espanol y aleman (los idiomas
        # del dataset de evaluacion y de los usuarios). Cada una se mide en el README.
        self.injection_patterns = [re.compile(p, re.IGNORECASE) for p in INJECTION_RULES]
        # Peticiones destructivas sobre datos ("borra la base de datos"): no son inyecciones,
        # pero el escudo las bloqueaba desde el principio; se mantienen como opcion aparte.
        self.destructive_patterns = [re.compile(p, re.IGNORECASE) for p in DESTRUCTIVE_RULES] if block_destructive else []
        if injection_detector not in {"rules", "classifier", "hybrid"}:
            raise ValueError("injection_detector debe ser 'rules', 'classifier' o 'hybrid'")
        self.injection_detector = injection_detector
        self.injection_threshold = injection_threshold
        self._classifier = None

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

    @property
    def classifier(self):
        if self._classifier is None:
            from .injection import default_classifier

            self._classifier = default_classifier()
        return self._classifier

    def injection_score(self, prompt: str) -> float:
        """Probabilidad de inyeccion segun el clasificador aprendido."""
        return self.classifier.score(prompt)

    def detect_injection(self, prompt: str) -> dict:
        """Decide si ``prompt`` es una inyeccion. Devuelve ``is_injection``, ``by`` (``rule``,
        ``classifier`` o vacio), ``rule`` (el patron que salto) y ``score`` (si se calculo)."""
        result = {"is_injection": False, "by": "", "rule": "", "score": None}
        if self.injection_detector in {"rules", "hybrid"}:
            for pattern in self.injection_patterns:
                if pattern.search(prompt):
                    result.update(is_injection=True, by="rule", rule=pattern.pattern)
                    return result
        if self.injection_detector in {"classifier", "hybrid"}:
            score = self.injection_score(prompt)
            threshold = self.injection_threshold if self.injection_threshold is not None else self.classifier.threshold
            result["score"] = score
            if score >= threshold:
                result.update(is_injection=True, by="classifier")
        return result

    def validate_input(self, prompt: str) -> Tuple[bool, str, str]:
        """
        Analiza un prompt de entrada aplicando politicas de seguridad.
        
        Returns:
            Tupla (is_safe: bool, processed_prompt: str, block_reason: str)
        """
        # 1. Comprobar Prompt Injection
        detection = self.detect_injection(prompt)
        if detection["is_injection"]:
            logger.warning(f"Intento de inyeccion bloqueado ({detection['by']})")
            return False, "", "Entrada bloqueada por sospecha de Prompt Injection / Jailbreak."
        for pattern in self.destructive_patterns:
            if pattern.search(prompt):
                logger.warning("Peticion destructiva bloqueada")
                return False, "", "Entrada bloqueada por sospecha de Prompt Injection / Jailbreak (orden destructiva)."
                
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
        # Bypass for default system responses/recommendations
        if generation.startswith("### 💡 Recomendación") or generation.startswith("¡Hola!"):
            return True, generation, ""
            
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
                
                # Si menos del 8% de los conceptos de la respuesta provienen del contexto original,
                # se asume que el modelo esta alucinando (inventando hechos no suministrados).
                if ratio < 0.08:
                    logger.warning(f"Hallucinacion detectada. Similitud factica: {ratio:.2f}")
                    return False, "", "Salida bloqueada debido a falta de consistencia factica con los documentos fuente (Alucinacion)."
                    
        return True, generation, ""
