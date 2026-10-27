# Running IMMUNE in 32 GB of memory

**English** | [繁體中文](memory-32gb.zh-TW.md)

The full stack used about 46 GB on the prototype device, which has 122.8 GB. This plan fits the same recovery loop into a machine with **32 GB in total** (29.8 GiB), where the CPU and the accelerator share that memory. The safety path is never reduced.

All sizes below are in GiB. "Measured" values come from the prototype device; "budget" values are targets that the validation steps at the end must confirm.

## 1. Where the memory went

| Part | Size | Source |
|---|---|---|
| Model weights (30B-class MoE, 3B active, 4-bit) | 17.8 | measured |
| KV cache reservation (8-bit KV) | ≈10 | measured; room for 41 sequences of 32k tokens |
| Reranker sidecar | 2.8 | measured (RSS) |
| Community knowledge index (158,881 records, SQLite FTS5) | a few MB | measured |
| Everything else: OS, agent sandbox, guardrails, services, test containers, engine overhead | ≈12 | remainder of the 46 GB total, not yet broken down |

Two observations drive the plan:

1. **The KV reservation is about 20 times larger than needed.** The engine serves at most 2 sequences, and the reservation holds 41 full 32k sequences. Two sequences need about 0.5 GiB.
2. **The model weights are the only part that cannot shrink without changing the model.** Everything else either shrinks by configuration or can be measured and capped.

## 2. Two profiles

| Part | Profile A: same model class | Profile B: smaller model |
|---|---|---|
| Model weights | 17.8 | ≤ 8 (8–14B dense or a small MoE, 4-bit) |
| KV cache, 2 sequences, 8-bit | 1.5 | 1.5 |
| Engine overhead (activations, graphs) | 1.5 | 1.5 |
| Reranker | off | 2.8 |
| OS | 1.5 | 1.5 |
| Agent runtime and sandbox | 1.5 | 1.5 |
| Guardrails service | 1.0 | 1.0 |
| Ops API, watchdog, reviewer, approval, dashboard | 0.5 | 0.5 |
| Target services under test | 0.5 | 0.5 |
| **Total** | **25.8** | **18.8** |
| **Headroom of 29.8** | **4.0** | **11.0** |

Profile A keeps the model that produced the measured results and runs with a thin margin. Profile B leaves room for every optional layer but needs the recovery bench rerun, because a smaller model can lower the recovery rate.

Start with Profile A. Fall back to B if A fails the memory checks in section 4.

## 3. Configuration

**Inference**
- At most 2 concurrent sequences, context up to 32k tokens, 8-bit KV.
- Size the KV pool for those 2 sequences (about 1.5 GiB) instead of as a fraction of total memory.
- Check the peak during model load. If the engine reads the weights into the page cache and then copies them to the accelerator, the load briefly needs two copies (about 36 GiB for Profile A), more than the machine has. Use a loader that streams the weights, or drop the page cache after loading.
- Run one inference server at a time. On the prototype device two servers at once froze the machine.
- Compile kernels ahead of time with limited parallel jobs (for example `MAX_JOBS=4`). Unbounded parallel compilation livelocked the prototype device.

**Optional layers, managed by the resource governor**
- Turn on `RESOURCE_GOVERNOR=1`. [`scripts/resource_governor.py`](../scripts/resource_governor.py) reads `MemAvailable` and chooses a mode:

  | Mode | Parallel specialists | Reranker | Community corpus |
  |---|---|---|---|
  | full | 2 | on | large |
  | reduced | 1 | on | small |
  | minimal | 0 | off | small |

- The defaults (`GOV_FULL_GB=20`, `GOV_REDUCED_GB=8`) suit the large machine. For 32 GB, start with `GOV_FULL_GB=8` and `GOV_REDUCED_GB=4`, then adjust after measuring.
- The governor never limits the main agent or the safety path.

**Protection against running out of memory**
- Give every service a memory cap (`MemoryMax=` in systemd, `--memory` in Docker). A service that grows past its cap is stopped alone instead of freezing the machine.
- Reserve memory for the safety path (`MemoryMin=` for the ops API, guardrails, watchdog and approval).
- Add a small compressed swap (zram, 4–8 GiB) as a buffer for short spikes, not for model weights.
- Set the out-of-memory order: reranker first, then the dashboard. Never the ops API, guardrails, watchdog or approval.

**What is never reduced**
- Policy gates, the allow-list, guardrails, two-key review, human approval, verification, the audit trail and incident memory.

## 4. Validation

Run each step on the 32 GB machine, with [`scripts/mem-profile.sh`](../scripts/mem-profile.sh) recording memory per service and container.

| Step | Check | Pass |
|---|---|---|
| 1. Breakdown | Profile the current stack at idle and during drills | the "everything else" row is split per service |
| 2. Load | Start the inference server alone | peak below 28 GiB |
| 3. Steady state | Start the full stack | `MemAvailable` ≥ 4 GiB for A, ≥ 8 GiB for B |
| 4. Load test | Run the same 27 drills over 15 fault types | `MemAvailable` never below 2 GiB; no safety-path service stopped |
| 5. Quality | Compare with the prototype device | recovery close to 23 of 27; 0 runs made worse; 0 false "healthy"; injected commands 3 of 3 blocked |
| 6. Speed | Incident to green on the three demo faults | report against 32–85 s |

Decision: if A passes steps 2–4, keep A and finish 5–6. If A fails 2–4, switch to B and repeat from step 2. If B fails step 5, compare candidate models on the same bench before choosing.

## 5. If the accelerator has its own memory

When the model runs on an accelerator with separate memory, 32 GB of system memory holds everything except the model and KV cache. The measured remainder is about 12 GiB plus the 2.8 GiB reranker, so the full profile fits without the reductions above. Only the accelerator's own memory needs the inference settings in section 3.
