"""Detector de inyección de prompts aprendido: regresión logística sobre n-gramas hasheados.

Sin dependencias más allá de NumPy. Las características son unigramas y bigramas de palabras y
n-gramas de caracteres (3 a 5) del texto en minúsculas y sin tildes, hasheados en 2^18
dimensiones con TF sublineal y norma L2 (formato CSR). El modelo se entrena por descenso de
gradiente completo con regularización L2; entrenar con las 546 frases de deepset/prompt-injections
lleva alrededor de un segundo, así que el detector por defecto se entrena al primer uso con el
split de entrenamiento que viaja dentro del paquete (``data/``) y no hay pesos binarios en el
repositorio.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import threading
import unicodedata
from dataclasses import dataclass
from typing import Iterable, List, Optional, Sequence, Tuple

import numpy as np

DIM = 1 << 18
_WORD = re.compile(r"\w+", re.UNICODE)
DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
TRAIN_FILE = os.path.join(DATA_DIR, "deepset_prompt_injections_train.jsonl")
# Negativos adicionales: preguntas reales de los splits de *entrenamiento* de NQ-open y HotpotQA.
# Sin ellos el modelo marcaba como inyección el 8-18 % de las preguntas normales (ver README).
BENIGN_FILE = os.path.join(DATA_DIR, "benign_questions_train.jsonl")


def _normalize(text: str) -> str:
    text = unicodedata.normalize("NFKD", text.lower())
    return "".join(c for c in text if not unicodedata.combining(c))


def _h(feature: str) -> int:
    return int.from_bytes(hashlib.blake2b(feature.encode("utf-8"), digest_size=8).digest(), "little") % DIM


def features(text: str) -> Tuple[np.ndarray, np.ndarray]:
    """Índices y valores (TF sublineal, norma L2) de un texto."""
    norm = _normalize(text)
    words = _WORD.findall(norm)
    counts: dict = {}
    for w in words:
        counts["w:" + w] = counts.get("w:" + w, 0) + 1
    for a, b in zip(words, words[1:]):
        key = f"b:{a} {b}"
        counts[key] = counts.get(key, 0) + 1
    squeezed = " ".join(words)
    for n in (3, 4, 5):
        for i in range(len(squeezed) - n + 1):
            key = f"c{n}:{squeezed[i:i + n]}"
            counts[key] = counts.get(key, 0) + 1
    merged: dict = {}
    for key, c in counts.items():
        idx = _h(key)
        merged[idx] = merged.get(idx, 0.0) + 1.0 + math.log(c)
    if not merged:
        return np.zeros(0, dtype=np.int64), np.zeros(0, dtype=np.float64)
    idx = np.fromiter(merged.keys(), dtype=np.int64, count=len(merged))
    val = np.fromiter(merged.values(), dtype=np.float64, count=len(merged))
    val /= np.linalg.norm(val)
    return idx, val


@dataclass
class CSR:
    indices: np.ndarray
    values: np.ndarray
    indptr: np.ndarray

    @classmethod
    def from_texts(cls, texts: Sequence[str]) -> "CSR":
        rows = [features(t) for t in texts]
        indptr = np.zeros(len(rows) + 1, dtype=np.int64)
        indptr[1:] = np.cumsum([len(i) for i, _ in rows])
        indices = np.concatenate([i for i, _ in rows]) if rows else np.zeros(0, dtype=np.int64)
        values = np.concatenate([v for _, v in rows]) if rows else np.zeros(0)
        return cls(indices, values, indptr)

    @property
    def n_rows(self) -> int:
        return len(self.indptr) - 1

    def dot(self, w: np.ndarray) -> np.ndarray:
        prod = w[self.indices] * self.values
        out = np.zeros(self.n_rows)
        nonempty = self.indptr[:-1] < self.indptr[1:]
        sums = np.add.reduceat(prod, self.indptr[:-1][nonempty]) if prod.size else np.zeros(0)
        out[nonempty] = sums
        return out

    def row_ids(self) -> np.ndarray:
        return np.repeat(np.arange(self.n_rows), np.diff(self.indptr))


def _sigmoid(z: np.ndarray) -> np.ndarray:
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


class InjectionClassifier:
    """Regresión logística binaria (1 = inyección) sobre :func:`features`."""

    def __init__(self, threshold: float = 0.5) -> None:
        self.w = np.zeros(DIM)
        self.b = 0.0
        self.threshold = threshold

    def fit(
        self,
        texts: Sequence[str],
        labels: Sequence[int],
        epochs: int = 300,
        lr: float = 2.0,
        l2: float = 1e-4,
        balanced: bool = True,
    ) -> "InjectionClassifier":
        X = CSR.from_texts(texts)
        y = np.asarray(labels, dtype=np.float64)
        rows = X.row_ids()
        n = len(y)
        # Pesos de clase: cada clase pesa lo mismo en la pérdida aunque haya más negativos.
        pos = max(1.0, float(y.sum()))
        neg = max(1.0, float(n - y.sum()))
        sw = np.where(y == 1, n / (2 * pos), n / (2 * neg)) if balanced else np.ones(n)
        # Adam sobre el gradiente completo: converge en pocas centenas de pasos y es determinista.
        m_w, v_w = np.zeros(DIM), np.zeros(DIM)
        m_b = v_b = 0.0
        beta1, beta2, eps = 0.9, 0.999, 1e-8
        step = lr * 0.01
        for t in range(1, epochs + 1):
            p = _sigmoid(X.dot(self.w) + self.b)
            err = (p - y) * sw
            g_w = np.bincount(X.indices, weights=X.values * err[rows], minlength=DIM) / n + l2 * self.w
            g_b = float(err.mean())
            m_w = beta1 * m_w + (1 - beta1) * g_w
            v_w = beta2 * v_w + (1 - beta2) * g_w * g_w
            m_b = beta1 * m_b + (1 - beta1) * g_b
            v_b = beta2 * v_b + (1 - beta2) * g_b * g_b
            corr1, corr2 = 1 - beta1**t, 1 - beta2**t
            self.w -= step * (m_w / corr1) / (np.sqrt(v_w / corr2) + eps)
            self.b -= step * (m_b / corr1) / (math.sqrt(v_b / corr2) + eps)
        return self

    def predict_proba(self, texts: Sequence[str]) -> np.ndarray:
        return _sigmoid(CSR.from_texts(texts).dot(self.w) + self.b)

    def score(self, text: str) -> float:
        return float(self.predict_proba([text])[0])

    def is_injection(self, text: str) -> bool:
        return self.score(text) >= self.threshold

    def save(self, path: str) -> None:
        nz = np.nonzero(self.w)[0]
        np.savez_compressed(path, idx=nz, w=self.w[nz], b=self.b, threshold=self.threshold)

    @classmethod
    def load(cls, path: str) -> "InjectionClassifier":
        data = np.load(path)
        clf = cls(float(data["threshold"]))
        clf.w[data["idx"]] = data["w"]
        clf.b = float(data["b"])
        return clf


def training_data() -> Tuple[List[str], List[int]]:
    """El split de entrenamiento de deepset más las preguntas benignas de entrenamiento."""
    texts, labels = read_jsonl(TRAIN_FILE)
    extra_t, extra_l = read_jsonl(BENIGN_FILE)
    return texts + extra_t, labels + extra_l


def read_jsonl(path: str) -> Tuple[List[str], List[int]]:
    texts, labels = [], []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            if line.strip():
                row = json.loads(line)
                texts.append(row["text"])
                labels.append(int(row["label"]))
    return texts, labels


def choose_threshold(texts: Sequence[str], labels: Sequence[int], folds: int = 5, seed: int = 0) -> float:
    """Umbral que maximiza F1 en validación cruzada sobre los datos de entrenamiento (nunca
    sobre los de prueba)."""
    order = np.random.RandomState(seed).permutation(len(texts))
    scores = np.zeros(len(texts))
    for f in range(folds):
        test = order[f::folds]
        train = np.setdiff1d(order, test)
        clf = InjectionClassifier().fit([texts[i] for i in train], [labels[i] for i in train])
        scores[test] = clf.predict_proba([texts[i] for i in test])
    y = np.asarray(labels)
    best_t, best_f1 = 0.5, -1.0
    for t in np.linspace(0.05, 0.95, 91):
        pred = scores >= t
        tp, fp, fn = int((pred & (y == 1)).sum()), int((pred & (y == 0)).sum()), int((~pred & (y == 1)).sum())
        f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
        if f1 > best_f1:
            best_t, best_f1 = float(t), f1
    return round(best_t, 2)


# Umbral elegido con choose_threshold(training_data()) (5 pliegues, semilla 0); ver README.
DEFAULT_THRESHOLD = 0.58
_default: Optional[InjectionClassifier] = None
_lock = threading.Lock()


def default_classifier() -> InjectionClassifier:
    """El detector entrenado con el split de entrenamiento incluido, construido una vez."""
    global _default
    with _lock:
        if _default is None:
            texts, labels = training_data()
            _default = InjectionClassifier(DEFAULT_THRESHOLD).fit(texts, labels)
        return _default


def confusion(predictions: Iterable[bool], labels: Iterable[int]) -> dict:
    tp = fp = fn = tn = 0
    for p, y in zip(predictions, labels):
        if p and y:
            tp += 1
        elif p:
            fp += 1
        elif y:
            fn += 1
        else:
            tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": precision, "recall": recall, "f1": f1}
