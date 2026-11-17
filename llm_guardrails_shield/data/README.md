# Data shipped with the shield

| File | Source | License | Use |
| --- | --- | --- | --- |
| `deepset_prompt_injections_train.jsonl` | [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections), split `train` (546 rows, 203 injections) | CC BY 4.0 | training the classifier |
| `deepset_prompt_injections_test.jsonl` | same dataset, split `test` (116 rows, 60 injections) | CC BY 4.0 | evaluation and the CI gate only — never training |
| `benign_questions_train.jsonl` | 600 questions of [NQ-open](https://github.com/google-research-datasets/natural-questions) `train` (CC BY-SA 3.0) and 600 of [HotpotQA](https://hotpotqa.github.io/) `train` (CC BY-SA 4.0) | as the sources | extra benign examples for training |
| `baseline_test.json` | precision and recall of the `hybrid` detector on the test split | — | CI gate |

Only the format was changed (`{"text", "label"}` per line, 1 = injection).
