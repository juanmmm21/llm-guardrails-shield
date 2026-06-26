# LLM Guardrails Shield

Un cortafuegos de seguridad bidireccional modular (Guardrails) diseñado para mitigar riesgos en aplicaciones que consumen modelos de lenguaje. Este sistema actua de forma intermedia interceptando las entradas enviadas por los usuarios (previniendo ataques informaticos y fugas de privacidad) y las salidas producidas por el modelo (evitando fugas de secretos y alucinaciones no alineadas con el contexto).

## Arquitectura de Proteccion Bidireccional

El escudo opera en dos fases criticas del flujo de ejecucion:

### 1. Guardrail de Entrada (Input Safeguards)
*   **Mitigacion de Prompt Injection:** Analiza el prompt contra expresiones regulares y firmas conocidas de ataques como jailbreaks, anulacion de instrucciones del sistema ("ignore all previous instructions"), y suplantacion de identidad del sistema.
*   **Anonimizador de Privacidad (PII Redactor):** Escanea correos electronicos y numeros de telefono movil, sustituyendolos por placeholders seguros (`[EMAIL]`, `[PHONE]`) para evitar que informacion sensible sea enviada a APIs de terceros.
*   **Detector de Toxicidad:** Contrasta el texto de entrada con una lista negra de terminos ofensivos y groserias locales en español, bloqueando la peticion si se detecta lenguaje abusivo.

### 2. Guardrail de Salida (Output Safeguards)
*   **Bloqueador de Fuga de Secretos:** Verifica si la respuesta generada por el LLM contiene claves de API expuestas (OpenAI, Google) o credenciales de configuracion, reteniendo la emision de ser necesario.
*   **Verificacion de Consistencia RAG (Fact-Checking):** Compara el solapamiento termico-semantico de la respuesta con el contexto recuperado de la base de datos vectorial. Si la respuesta contiene conceptos no soportados en el contexto (umbral inferior al 15%), bloquea la salida alertando de alucinacion.

## Requisitos e Instalacion

*   Python 3.8 o superior
*   Pydantic

Para instalar las dependencias locales, ejecute:

```bash
pip install -r requirements.txt
```

## Pruebas y Verificacion

1.  **Ejecutar Suite de Pruebas Unitarias:**
    ```bash
    python -m unittest test_shield.py
    ```
2.  **Ejecutar Demostracion Interactiva:**
    ```bash
    python example.py
    ```
    El script demostrara la proteccion activa ante intentos de inyeccion, anonimizacion de numeros de telefono y deteccion de alucinaciones en RAG.
