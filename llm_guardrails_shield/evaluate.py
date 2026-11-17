"""``python -m llm_guardrails_shield.evaluate``: precisión y recall de la detección de inyecciones.

    python -m llm_guardrails_shield.evaluate                       # test de deepset, los tres modos
    python -m llm_guardrails_shield.evaluate --gate llm_guardrails_shield/data/baseline_test.json
    python -m llm_guardrails_shield.evaluate --benign otras_preguntas.jsonl   # tasa de falsos positivos

Un JSONL etiquetado tiene ``{"text": ..., "label": 0|1}`` por línea (1 = inyección); uno de
textos benignos puede llevar ``text`` o ``question``. ``--gate`` termina con código 1 si la
precisión o el recall del modo ``hybrid`` bajan de la línea base: es lo que ejecuta la CI.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from typing import List, Optional

from .injection import DATA_DIR, confusion, read_jsonl
from .shield import LLMGuardrailsShield

TEST_FILE = os.path.join(DATA_DIR, "deepset_prompt_injections_test.jsonl")
MODES = ("rules", "classifier", "hybrid")


def predictions(shield: LLMGuardrailsShield, texts: List[str]) -> List[bool]:
    return [bool(shield.detect_injection(t)["is_injection"]) for t in texts]


def benign_texts(path: str) -> List[str]:
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                out.append(row.get("text") or row.get("question") or "")
    return out


def main(argv: Optional[List[str]] = None) -> int:
    logging.disable(logging.WARNING)
    parser = argparse.ArgumentParser(prog="llm_guardrails_shield.evaluate")
    parser.add_argument("path", nargs="?", default=TEST_FILE)
    parser.add_argument("--benign", action="append", default=[], help="JSONL de textos benignos")
    parser.add_argument("--gate", help="JSON con precision/recall mínimos del modo hybrid")
    parser.add_argument("--tolerance", type=float, default=0.02)
    parser.add_argument("--write", help="guarda precision/recall del modo hybrid como línea base")
    args = parser.parse_args(argv)

    texts, labels = read_jsonl(args.path)
    print(f"{os.path.basename(args.path)}: {len(texts)} textos, {sum(labels)} inyecciones")
    print("| Detector | Precision | Recall | F1 | TP | FP | FN | TN | ms/text |")
    print("|---|---|---|---|---|---|---|---|---|")
    results = {}
    for mode in MODES:
        shield = LLMGuardrailsShield(injection_detector=mode)
        if mode != "rules":
            shield.classifier  # entrenar fuera del cronómetro
        start = time.perf_counter()
        preds = predictions(shield, texts)
        ms = (time.perf_counter() - start) * 1000 / max(1, len(texts))
        c = confusion(preds, labels)
        results[mode] = c
        print(
            f"| {mode} | {c['precision']:.3f} | {c['recall']:.3f} | {c['f1']:.3f} | "
            f"{c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {ms:.2f} |"
        )
    for path in args.benign:
        benign = benign_texts(path)
        print(f"\nFalsos positivos en {os.path.basename(path)} ({len(benign)} textos benignos):")
        for mode in MODES:
            flagged = sum(predictions(LLMGuardrailsShield(injection_detector=mode), benign))
            print(f"  {mode}: {flagged} ({flagged / max(1, len(benign)):.1%})")

    hybrid = {"precision": round(results["hybrid"]["precision"], 4), "recall": round(results["hybrid"]["recall"], 4)}
    if args.write:
        with open(args.write, "w", encoding="utf-8") as fh:
            json.dump(hybrid, fh, indent=2)
    if args.gate:
        with open(args.gate, encoding="utf-8") as fh:
            base = json.load(fh)
        problems = [
            f"{k}: {hybrid[k]:.4f} < {base[k]:.4f} - {args.tolerance}"
            for k in ("precision", "recall")
            if hybrid[k] < base[k] - args.tolerance
        ]
        if problems:
            print("REGRESIÓN:\n  " + "\n  ".join(problems))
            return 1
        print("Sin regresiones frente a", args.gate)
    return 0


if __name__ == "__main__":
    sys.exit(main())
