"""Verifies that an exported ONNX model gives the same verdicts as scikit-learn before
export. Validation bridge between the training entry points (scikit-learn) and the
agent's inference (`ort` in crates/ml).

Usage: python -m synthaea_ml.export.verify_onnx [model.onnx ...]
Defaults to every `model.onnx` under ml/registry/.
"""

import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort

from synthaea_ml.features.cmdline import extract_features
from synthaea_ml.training.train_windows import SANITY_CHECK_SAMPLES

REGISTRY = Path(__file__).resolve().parents[2] / "registry"


def verify(model_path: Path) -> None:
    session = ort.InferenceSession(str(model_path))
    input_name = session.get_inputs()[0].name
    output_names = [o.name for o in session.get_outputs()]
    print(f"{model_path}: input {input_name}, outputs {output_names}")

    for label, cmdline in SANITY_CHECK_SAMPLES.items():
        feats = np.array([extract_features(cmdline)], dtype=np.float32)
        outputs = session.run(None, {input_name: feats})
        result = dict(zip(output_names, outputs, strict=True))
        label_out = result.get("label")
        score_out = result.get("scores")
        verdict = "ANOMALY" if label_out is not None and label_out[0] == -1 else "normal"
        print(f"  {label}: label={label_out} scores={score_out} -> {verdict}")


def main() -> None:
    models = [Path(p) for p in sys.argv[1:]] or sorted(REGISTRY.glob("*/*/model.onnx"))
    if not models:
        sys.exit(f"no model.onnx found under {REGISTRY} and none given on the command line")
    for model in models:
        verify(model)


if __name__ == "__main__":
    main()
