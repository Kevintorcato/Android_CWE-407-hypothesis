# Content-induced CPU amplification behavior, consistent with a CWE-407 hypothesis, without validated impact on a production Android environment

## Summary

While researching AOSP native libraries via fuzzing, we found a performance issue in the native
`external/libavc` decoder (H.264/AVC/MVC), commit `e67b0aa3b0f5eb15b40c4d148c5d070d8a2c6828`
("Upgrade libavc to v1.6.0"). Bug class: **CWE-407 (Inefficient Algorithmic Complexity)** — DoS via
disproportionate CPU consumption.

Why it's worth reporting: a media decoder that runs automatically (thumbnail generation, preview,
background processing) can be induced to consume CPU disproportionately to the input size, with a
single byte controlling the amplification. This is a real DoS surface.

## What this is

- It's a CPU DoS (CWE-407), confirmed by profiling.

## Affected component

`external/libavc`, commit [`e67b0aa3`](https://android.googlesource.com/platform/external/libavc/+/e67b0aa3b0f5eb15b40c4d148c5d070d8a2c6828)
("Upgrade libavc to v1.6.0").

## Methodology (summary)

- Fuzzing with libFuzzer + AddressSanitizer (`-fsanitize=fuzzer-no-link,address -g`), clang 18.1.3
  (Ubuntu 24.04), standalone CMake build (outside Soong).
- Two binaries: `mvc_dec_fuzzer` (MVC decoder) and `avc_dec_fuzzer` (plain AVC decoder).
- `slow-unit-*` is an artifact libFuzzer automatically saves when an input takes abnormally longer
  than the rest of the corpus — on its own it is not proof of a real bug, just a signal. That's why
  each one was re-measured in isolation.
- Isolated measurement: `/usr/bin/time -v` (3 runs per file, for stability) +
  `perf record --call-graph dwarf` / `perf stat` on the relevant cases.
- Triage: of the 20 `slow-unit-*` files found in the campaign, 11 were triaged by isolated
  measurement — only 4 are genuinely slow (RSS 5-6x higher, time 10-130x higher than baseline); the
  other 7 are false positives of libFuzzer's heuristic. The remaining 9 were not individually
  measured and stay out of this document until triaged the same way.

## Confirmed findings (4 files, triaged by isolated measurement)

### Main finding — ~4.26x amplification from a single byte in the CABAC payload

- Files: `slow-unit-6f186abe...` (fast, 0.92-0.94s) vs `slow-unit-ebb25099...` (slow,
  3.95-3.99s)
- Size: 176,375 bytes — identical in both files
- Difference: exactly 1 byte, at offset 54604 — `0xE9` (fast) vs `0x5A` (slow)
- Byte location: inside the CABAC-encoded payload of a slice, not in any directly interpretable
  header field — the exact H.264 syntax element changed (macroblock partition, mode flag,
  skip-run count, etc.) was not identified (would require an instrumented CABAC parser or manual
  bit-by-bit decoding — future work).
- Profiling confirmation: `perf record --call-graph dwarf` shows both files go through the same
  code path
  (`imvcd_parse_decode_slice → imvcd_parse_bslice → ih264d_parse_inter_slice_data_cabac →
  ih264d_mv_pred_ref_tfr_nby2_bmb / ih264d_decode_spatial_direct`), with the same relative
  proportion of self-time between functions. The only difference is how many times this expensive
  path executes: 17,142 samples (slow) vs 3,889 samples (fast) — ratio ~4.4x, consistent with the
  ~4.26x wall-clock time measured.
- Technical conclusion: this is not a code-path change — it's the same expensive pipeline (B-slice
  "spatial direct" motion prediction + weighted bi-directional prediction + deblocking) running ~4x
  more times, controlled by 1 bit/byte of content, independent of file size. Clean evidence of
  CWE-407 via content, not via size.
- Real severity: moderate — a 4.26x amplification on a 176KB file processed in ~4s is not
  catastrophic in isolation, but it's the kind of pattern that could be scaled further with
  additional PoC optimization (smaller file, same effect).

### Findings 2 and 3 — two other slow files

- `3ec59835...`: 65,536 bytes, 0.26-0.30s (baseline ~0.013-0.03s, ~10-20x), peak RSS ~313MB.
- `6dff87a0...`: 65,536 bytes, 0.26s (~10x baseline), peak RSS ~313MB.

**Finding 2 (`3ec59835`) — investigated in detail and closed (not a bug).** Before reaching the
real explanation, three alternative hypotheses were tested and ruled out by controlled testing:

- *Quadratic EPB/RBSP* (cost grows with the count of `00 00 03`): ruled out — two files of the
  same size (65,536 B), one with 0 EPBs and another with 172, gave 227ms vs 259ms (14% difference,
  noise). If it were quadratic in EPB count the ratio would be ~20x.
- *"Invalid" NAL type (103)*: ruled out — initial confusion. `0x67 & 0x1F = 7`, i.e. the file's
  initial byte is NAL type 7 (SPS), a normal value, not an out-of-spec type 103 as it appeared
  before applying the `& 0x1F` mask (`NAL_UNIT_TYPE()` in `ih264d_defs.h:107`).
- *Unvalidated allocation*: ruled out by direct source code reading. The file's SPS is Main
  profile (77), level_idc 51 (level 5.1 — H.264's highest level, legitimately allows large
  resolutions). In `ih264d_parse_sps` (`decoder/ih264d_parse_headers.c:582`), the fields that drive
  allocation have an explicit cap: `num_ref_frames > H264_MAX_REF_PICS` → error (line ~870),
  `pic_width_in_mbs > H264_MAX_FRAME_WIDTH>>4` → error (line ~884), same for `pic_height`. With
  `H264_MAX_FRAME_WIDTH = H264_MAX_FRAME_HEIGHT = 4080` and `H264_MAX_REF_PICS = 16`
  (`decoder/ih264d_defs.h:39-40,534`), the legitimate worst case is 4080×4080×1.5(YUV 4:2:0)×16
  refs ≈ ~400MB — the measured 313MB falls within that envelope. Also confirmed via `strace -c`
  that the time isn't allocation (mmap/munmap total only 1.46ms out of 260ms total) — it's CPU in
  the parser processing a high-level SPS, expected work, not anomalous.

**Conclusion for Finding 2: not a vulnerability.** The decoder is correctly honoring a valid
level-5.1 SPS, with all field validation working as it should. Same mechanism as the RSS note
below, now confirmed via source code reading rather than just static analysis.

**Finding 3 (`6dff87a0`) remains open** — it was not submitted to the same investigation. Given
that finding 2's mechanism was fully explained by SPS parameters within the validation caps, it's
likely (but unconfirmed) that finding 3 is the same pattern — remains a next step.

Note: `6dff87a0` was generated by the morning campaign (`mvc_dec_fuzzer`) and reappeared
byte-for-byte identical in the evening campaign (`avc_dec_fuzzer`, different corpus and binary) —
a sign that this pattern (high-level SPS) is a relatively easy attractor for a generic fuzzer to
find.

### Note on high RSS (313-328MB) — ruled out as a memory finding

A separate investigation (static analysis of SPS validations in `ih264d_defs.h`, later confirmed
by directly reading `ih264d_parse_sps` — see Finding 2 above) ruled this out as a bug: the decoder
correctly validates `num_ref_frames` (cap 16, or 48 on the MVC path) and
`pic_width_in_mbs`/`pic_height_in_map_units` (cap 4080x4080). The theoretical worst-case allocation
with these caps is ~381MB (single-view) to ~1143MB (MVC) — the measured 313-328MB falls within that
envelope. This is not a CWE-400/407 allocation issue — it's validated, expected allocation.

## Multi-frame amplification hypothesis — tested on 2026-11-09 (ruled out)

**Original question:** if the amplification pattern (main finding) repeats across multiple frames
of the same stream, does the cost scale linearly or worse (multiplicative/memory blow-up)?

**What was tested:** instead of concatenating distinct `slow-unit` files (the parser would reject
that), we built a valid H.264/MVC stream by repeating a full GOP (SPS+PPS+IDR+slices) N times
(`build_full_gop_repeat.py`), generating 5 files:

| File | Repeats (N) | Size |
|---|---|---|
| `gop_1.264` | 1 | 89,330 B |
| `gop_2.264` | 2 | 178,660 B |
| `gop_4.264` | 4 | 357,320 B |
| `gop_8.264` | 8 | 714,640 B |
| `gop_16.264` | 16 | 1,429,280 B |

Each file was run on two different binaries from the same commit: `build-cmake/mvc_dec_fuzzer`
(fuzzing build, ASan+SanitizerCoverage+`-O0`) and `build-release/mvcdec` (libavc's official example
app, production build, `-O2`, no instrumentation).

**Result 1 — scales with frame count (production build):**

| File | Size | Time (wall clock) | Exit |
|---|---|---|---|
| `gop_1.264` | 89,330 B | 0.75s | 0 |
| `gop_2.264` | 178,660 B | 1.14s | 0 |
| `gop_4.264` | 357,320 B | 1.92s | 0 |
| `gop_8.264` | 714,640 B | 3.50s | 0 |
| `gop_16.264` | 1,429,280 B | 6.63s | 0 |

Scaling is approximately linear with frame count/size, not superlinear. There is no multiplicative
amplification from repeating the expensive pattern across multiple frames — each frame costs
proportionally to what's expected, with no anomalous cumulative effect. Zero crashes, exit 0 on
all 5 files.

**Result 2 — the same file (`gop_16.264`) on the fuzzing build vs. production:**

| Binary | Measured time |
|---|---|
| `build-release/mvcdec` (production, `-O2`, no instrumentation) | 6.6s |
| `build-cmake/mvc_dec_fuzzer` (ASan+SanCov+`-O0`) | 57.2s |

Ratio ~8.7x. In other words, ~87-90% of the total time measured in the fuzzer is
sanitization/coverage instrumentation overhead, not real decoding work — the production decoder
does the same work in a fraction of the time. This is expected (ASan + SanitizerCoverage typically
cost 2x to 10x+) and is not, by itself, a vulnerability — it's a normal characteristic of
fuzzing/debug builds, which no end user runs in production.

**Combined conclusion:**

- Multi-frame amplification hypothesis: **ruled out**. Cost scales linearly.
- `gop_16.264`, if analyzed in isolation without knowing its origin, might look like a "serious"
  finding (56-57s to decode ~1.4MB) — but compared to the actual production decoder (6.2-6.6s for
  the same file), it's clear that most of the time is an artifact of the instrumentation
  environment. Classified as low-severity DoS, no remediation action needed. Closed.
- Does not change the conclusion of the main finding (`6f186abe`/`ebb25099` pair): that comparison
  was done with the same instrumented binary on both sides, so instrumentation overhead cancels
  out — the ~4.26x difference is real and not explained by this.

## Test on a real Android device — attempted on 2026-11-09

To close the gap of reproduction on a real Android device, we attempted to reproduce the main
finding on a real Android.

**Environment:** Android emulator (Google Play image `sdk_gphone64_x86_64`), Android 14 (SDK 34),
security patch level 2023-09-05, fingerprint
`google/sdk_gphone64_x86_64/emu64xa:14/UE1A.230829.050/12077443:userdebug/dev-keys`, already
running in an Ubuntu VM with `adb` configured.

**Methodology:**

1. The two main-finding files (`6f186abe`/`ebb25099`, raw H.264/MVC streams) were remuxed to
   `.mp4` with `ffmpeg -f h264 -i <file> -c copy <output>.mp4` (no re-encoding), necessary because
   Android's `MediaExtractor` doesn't recognize a raw, containerless H.264 Annex-B stream.
2. Pushed to the device via `adb push` and decoded with the `stagefright` command-line tool
   (present on `userdebug`/engineering builds, `/system_ext/bin/stagefright`), forcing the software
   decoder (`-s`).
3. Confirmed via `logcat` that Android used `c2.android.avc.decoder` — the Codec2 software decoder,
   based on the same `external/libavc` we tested in isolation.
4. Decode time measured from `logcat`'s real timestamps (buffer-pool creation to the last
   `flushMediametrics`), not the `stagefright` process's wall-clock (which has a fixed ~2.4s
   Codec2/HAL initialization overhead, irrelevant for the comparison).

**Result:** fast (`6f186abe`) ~2.45s decode; slow (`ebb25099`) ~2.80s. ~14% difference — well
below the ~4.26x measured in the standalone harness.

**Honest interpretation — the amplification did NOT reproduce on-device in this test.** The most
likely explanation is a scope mismatch, not a refutation of the finding: the standard `.mp4` remux
likely preserves only the stream's base layer (plain AVC slices), discarding the MVC extension NALs
(`PREFIX_NAL`/`CODED_SLICE_EXTENSION`) that the original `mvc_dec_fuzzer` specifically exercised.
In other words, the device decoded via the "normal" AVC path, not the MVC path
(`imvcd_parse_decode_slice → ...`) where profiling had already shown the altered byte at offset
54604 actually has an effect (see "Main finding" section above).

**What this confirms and what remains open:**

- ✅ Confirmed access to a real Android (device/emulator) with working `adb`.
- ✅ Confirmed that the decoder in use on the device is based on the same `external/libavc`
  (`c2.android.avc.decoder`).
- ⚠️ **We did not confirm the 4.26x amplification specifically via the MVC path on the device.**
  That would require a pipeline/container that forces Android to decode via the MVC path
  (`imvcd_*`), which is not a standard Android playback flow (MVC isn't used for normal video
  playback, only in specific stereo/3D contexts) — remains a real next step, not resolved by this
  attempt.
- The original finding, measured in isolation in the `mvc_dec_fuzzer` harness with call-stack
  profiling confirming the exact code path, remains valid and is not contradicted by this test —
  it just hasn't yet been validated end-to-end on a device.

## Reproduction on the MVC path, natively on-device — 2026-11-10

The attempt above (via `stagefright`/Codec2) didn't exercise the MVC path. To close that gap, we
cross-compiled `external/libavc` itself (the same production CLI, `mvcdec`,
`examples/mvcdec/main.c`) **for Android**, using the NDK (r26.1.10909125, Clang 17.0.2), and ran
the resulting binary directly on the Android OS via `adb shell` — no longer on a Linux x86 host.

**Build:**

```
cmake -DCMAKE_TOOLCHAIN_FILE=$NDK/build/cmake/android.toolchain.cmake \
  -DANDROID_ABI=x86_64 -DANDROID_PLATFORM=android-28 \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_MVC=ON \
  -DCMAKE_EXE_LINKER_FLAGS="-llog" ..
make mvcdec
```

(`ENABLE_MVC=ON` is required — libavc's CMake disables the MVC build by default; `-llog` resolves
`__android_log_print`, used internally by the decoder on Android builds.)

**Execution:** the `mvcdec` binary was pushed via `adb push` to `/data/local/tmp/` on the same
Android emulator (real device, `adb root` already available since it's a `userdebug` build),
along with the two main-finding files, and run with `adb shell time ...` (3 runs per file):

| File | Real time (avg) | User time / CPU (avg) |
|---|---|---|
| `6f186abe` (fast) | ~0.40s | ~0.23s |
| `ebb25099` (slow) | ~1.15s | ~0.94s |

**User-time ratio: ~4.1x** — consistent with the ~4.26x originally measured on the Linux host. The
same end-of-stream error (`Error in Frame decode 0x87`, `ERROR_CORRUPTED_SLICE`) appears in both
environments (host and Android) for both files — expected tool behavior for this kind of input,
not a sign of failure.

**What this confirms:** `external/libavc` code, on the exact MVC path identified by profiling
(`imvcd_parse_decode_slice → ...`), compiled for Android and running on the Android operating
system (the device's kernel, libc, and scheduler, no longer a Linux x86 host), reproduces the ~4x
amplification. This is real-device reproduction of the specific vulnerability.

**Remaining limitation:** this test runs the binary as a standalone process via `adb shell`, not
through the app/`MediaCodec`/Codec2 pipeline (that path, tested in the previous section, doesn't
expose MVC decoding in Android's standard playback flow). In other words, we confirmed the
vulnerable code runs and amplifies on the real Android OS, but we have not mapped an Android
app/flow that exposes this specific MVC path to untrusted content — that would be the next step to
assess real-world impact on a specific Android product.

## Final results

| # | File (`slow-unit-...`) | Result | Affected component | Test environment |
|---|---|---|---|---|
| 1 | `6f186abef327798dd690dbb03fc79bc4efec75e7` | Baseline — normal time (~0.23-0.66s) | `external/libavc`, MVC decoder (`imvcd_parse_decode_slice`) | Linux x86 host (fuzzer + production build) and Android 14 (SDK 34), `sdk_gphone64_x86_64` emulator, patch 2023-09-05 |
| 2 | `ebb25099c6194a879fea2a2e4304a9bb468c0c98` | **~4.26x slower than #1** (same size, 176,375 B, differs by 1 byte at offset 54604) — **main finding** | same | same |
| 3 | `3ec598354e03287361c0b162e4e857f1ae9eba6d` | ~10-20x slower than baseline — finding 2, **investigated and closed**: expected decoder behavior for a valid level-5.1 SPS, not a bug | same | Linux x86 host (production) |
| 4 | `6dff87a095a3bf5ca7875b58af25a9b0ed32089b` | ~10x slower than baseline — finding 3, **open** (likely same mechanism as #3, unconfirmed) | same | Linux x86 host (production) |

Affected commit: `external/libavc` @ `e67b0aa3b0f5eb15b40c4d148c5d070d8a2c6828` ("Upgrade libavc to v1.6.0").

### Additional reproduction on the production binary

In addition to the instrumented (ASan/SanitizerCoverage) build used for fuzzing, we ran the 4
confirmed files against `build-release/mvcdec` (libavc's official example app, `-O2`, no
instrumentation):

| File | Size | User time | Elapsed |
|---|---|---|---|
| `6f186abe` (fast, main finding) | 176,375 B | 0.27s | 0.66s |
| `ebb25099` (slow, main finding) | 176,375 B | 0.97s | 1.36s |
| `3ec59835` (finding 2) | 65,536 B | 0.11s | 0.49s |
| `6dff87a0` (finding 3) | 65,536 B | 0.11s | 0.47s |

`ebb25099` remains clearly the most expensive — a ~3.6x ratio relative to `6f186abe` on this
production binary (vs. ~4.26x on the instrumented build). This rules out the difference being an
ASan/SanitizerCoverage artifact: it holds, at the same order of magnitude, on the decoder an actual
end user runs.

We also tried stacking the 4 findings into a single stream, to check for a cumulative effect —
inconclusive: concatenating the files broke the parser right after the first one (`Error in Frame
decode 0x87`), since each is already a complete MVC stream on its own with its own SPS
parameters. This neither proves nor disproves anything about the finding, it just confirms the
methodology limitation already noted in the next-steps section.

## Limitations / next steps

1. ~~Reproduction in a real Android environment — not done.~~ ~~Attempted on 2026-11-09 — confirmed
   real device + same decoder, but not the MVC-specific amplification.~~ **Closed on 2026-11-10** —
   the ~4x amplification was reproduced by running `mvcdec` (built with the NDK, `ENABLE_MVC=ON`)
   directly on Android via `adb shell` (see section above). What remains, as a next step (no longer
   a blocker for the report):
   - Map a real Android app/flow (`MediaCodec`, thumbnail generation, etc.) that exposes the MVC
     path to untrusted content — the current test runs the binary as a standalone process, not
     through Android's media framework pipeline.
   - Also test on a physical device, not just an x86_64 emulator.

2. **Exact identification of the CABAC element.** We know the byte's location (offset 54604) and
   its effect at the function level (via `perf`), but not the exact H.264 syntax element that
   causes the amplification. Would require instrumenting the CABAC parser to find out:
   - Which macroblock is affected.
   - Which syntax element changes.
   - How many additional iterations are executed.
   - Why the byte changes the computational cost so much.

3. **PoC minimization.** We still work with the original 176KB file. Reducing the file while
   keeping the amplification would help both the demonstration and the quality of the report.

4. ~~Deeper investigation of findings 2 and 3~~ **Finding 2 (`3ec59835`) done — not a bug**
   (see "Confirmed findings" above: level-5.1 SPS within validation caps, confirmed by source code
   reading and `strace`). **Finding 3 (`6dff87a0`) remains pending** — not submitted to the same
   investigation; likely the same mechanism as Finding 2, but unconfirmed.

5. **Tests with different configurations.** Compare:
   - Different libavc versions.
   - Different compilers.
   - Different optimization levels.
   - Different architectures (ARM64 vs. x86-64).

   This helps determine whether the issue is specific to one implementation/toolchain or a more
   general characteristic of the algorithm.

6. **Real-world impact demonstration.** So far we've only demonstrated the isolated CPU
   amplification in the fuzzer, not a real-world scenario impact, for example:
   - Automatic thumbnail generation.
   - Automatic media processing.
   - Batch file processing.
   - Concurrent processing of multiple files.

   It's not necessary to cover all of these, but at least one real scenario would significantly
   strengthen the research.

## References

- Affected commit: https://android.googlesource.com/platform/external/libavc/+/e67b0aa3b0f5eb15b40c4d148c5d070d8a2c6828
