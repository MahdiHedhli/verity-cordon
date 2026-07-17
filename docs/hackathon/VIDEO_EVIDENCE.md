# Build Week Video Evidence

## Final Local Render

- **Rendered**: 2026-07-17
- **Duration**: 83.930 seconds
- **Video**: H.264, 1280×720, 30 fps, YUV 4:2:0
- **Audio**: AAC mono, derived from the OmniVoice Studio `The Neighbor`
  narration mix
- **Container size**: 3,528,647 bytes
- **SHA-256**:
  `6e339cb6caf31cd338cb2e69b01acd4c1ed8fe88ad2ff295cd88405e256116bd`
- **Unlisted YouTube review URL**: https://youtu.be/c-a7sLusXv4
- **YouTube displayed duration**: 1:24
- **Public YouTube URL**: pending operator review and publication

The local render is intentionally excluded from Git. The checksum binds the
reviewed upload artifact without adding a binary release asset to the source
repository.

## Unlisted Review Upload

On 2026-07-17, the checksum-bound final render was saved to YouTube as an
**Unlisted** review upload at https://youtu.be/c-a7sLusXv4. YouTube reports a
1:24 duration, `yt-dlp` independently reports `unlisted` availability and an
84-second duration, and assignment to the existing `OpenAI Hack-a-thon`
playlist was verified. This is review evidence only: the operator has not yet
approved public visibility, and the Devpost submission has not been submitted.

## Narration Evidence

- **Voice**: OmniVoice Studio `The Neighbor`
- **Full WAV duration**: 83.930 seconds
- **Full WAV integrated loudness**: -16.0 LUFS
- **Full WAV true peak**: -1.5 dBFS
- **Full WAV SHA-256**:
  `0938cd6c665fa532216ff8109a01d125f83cd251d86a8ef4943f0c4bb074cab6`
- **Silence QA**: no interval at or below -45 dB lasting 1.25 seconds or
  longer

The narration identifies semantic assessment as advice and deterministic
policy as final authority. The Control Room visibly labels the recorded
semantic fixture used for the deterministic review path; this video is not
evidence of a live GPT-5.6 provider response.

## Visual Evidence Shown

The render uses causally ordered captures from the running local Control Room
and a terminal invoking the reviewed hook harness:

- The terminal invokes the reviewed, localhost-only poisoned-docs fixture
  through the normalized `PostToolUse` contract.
- In shadow mode, the Overview changes from zero to two decisions and the
  poisoned operational instruction is admitted with `actual_action=allow` and
  `would_have_action=quarantine`.
- Candidate detail shows sanitized content, tool-output provenance, detector
  findings, policy input, and the visibly labeled recorded semantic fixture.
- The policy is shown in enforcement mode and the identical fixture is invoked
  again.
- Quarantine review shows the poisoned operational instruction excluded from
  the active view under policy version `1.0.1`.
- The signed timeline records the quarantine decision and Ledger Verification
  reports a verified daemon chain state.

The browser tabs and automation banner were cropped from the public cut, and
the terminal prompt's operator username and hostname were redacted. The video
does not claim that the hook event originated inside Codex Desktop, does not
present a fresh-session injection or revocation demonstration, and does not
present a fixture response as live-model attestation. The synthetic tool
fixture performs no external transmission and reads no host secrets.

## Publication Gate

After operator review and before Devpost submission, change the approved upload
to **Public**, then verify while logged out that the public YouTube player is
reachable, reports a duration below three minutes, has audio enabled, and
includes the repository link. Replace the pending public URL in this file, the
submission draft, and the checklist only after that public verification.
