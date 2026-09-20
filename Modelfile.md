# ── Modelfile.q35a3b ──────────────────────────────────────────
FROM ./Qwen3.5-35B-A3B-UD-Q4_K_XL.gguf
PARAMETER num_ctx 102400
PARAMETER num_gpu 39
PARAMETER temperature 0.7
PARAMETER top_p 0.8
PARAMETER top_k 20
PARAMETER presence_penalty 1.0

# ── Modelfile.glm47flash ──────────────────────────────────────
FROM ./GLM-4.7-Flash-UD-Q4_K_XL.gguf
PARAMETER temperature 0.7
PARAMETER top_p 1.0
PARAMETER min_p 0.01
PARAMATER repeat_penalty 1.0

PARAMATER num_batch 512
PARAMATER num_thread 8