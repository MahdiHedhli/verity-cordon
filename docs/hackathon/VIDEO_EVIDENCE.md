# Build Week Video Evidence

## Submission Local Render

- **Rendered**: 2026-07-17
- **Duration**: 109.733 seconds
- **Video**: H.264, 1280×720, 30 fps, YUV 4:2:0
- **Audio**: AAC mono, derived from the OmniVoice Studio `The Neighbor`
  narration mix
- **Container size**: 4,437,776 bytes
- **SHA-256**:
  `b7167f6aedb156778315d89fb0b0ea032255b1f8acf55545df863dd142ce2ce0`
- **Public YouTube URL**: https://youtu.be/tREkD6WbolI
- **YouTube video ID**: `tREkD6WbolI`
- **Published**: 2026-07-17
- **YouTube displayed duration**: 1:50
- **Visibility**: Public
- **Playlist**: `OpenAI Hack-a-thon`
- **YouTube checks**: Copyright and Community Guidelines checks passed

The submission render preserves the reviewed 83.930-second causal live demo,
then holds its verified ledger frame while a 25.300-second OmniVoice Studio
`The Neighbor` addendum explicitly explains how Codex was used to build the
product and how GPT-5.6 contributes at runtime. A 0.5-second transition keeps
the final duration below three minutes. The local render is intentionally
excluded from Git; this checksum binds the publication artifact without adding
a binary release asset to the source repository.

## Public Submission Upload

On 2026-07-17, the checksum-bound 109.733-second submission render was
published as **Public** at https://youtu.be/tREkD6WbolI. YouTube displays a
1:50 duration, the video is assigned to the existing `OpenAI Hack-a-thon`
playlist, and YouTube reported that both its Copyright and Community
Guidelines checks passed. This is the video entered on the accepted Build Week
Devpost submission `1095381`.

## Superseded Unlisted Review Upload

On 2026-07-17, the checksum-bound superseded 83.930-second render was saved to
YouTube as an **Unlisted** review upload at https://youtu.be/c-a7sLusXv4.
YouTube reports a 1:24 duration, `yt-dlp` independently reports `unlisted`
availability and an 84-second duration, and assignment to the existing
`OpenAI Hack-a-thon` playlist was verified. This upload is not the submission
video because its voiceover does not explicitly explain the Codex development
contribution or name GPT-5.6. It remains review evidence only and must not be
entered on Devpost.

## Narration Evidence

- **Voice**: OmniVoice Studio `The Neighbor`
- **Base narration duration**: 83.930 seconds
- **Base narration integrated loudness**: -16.0 LUFS
- **Base narration true peak**: -1.5 dBFS
- **Compliance addendum duration**: 25.300 seconds
- **Compliance addendum SHA-256**:
  `44f84d084e5f306a32dd697991363ef3517d7b9f4c2c9d2b85f4e7784bbc6767`
- **Local ASR QA**: the generated addendum was transcribed back as naming
  OpenAI Codex, GPT-5.6, structured candidate extraction, semantic risk
  assessment, local secret sanitization, deterministic policy authority, and
  the recorded semantic fixture
- **Silence QA**: no interval at or below -45 dB lasting 1.25 seconds or
  longer

The addendum states that Codex was the build partner for primary-source
research, Spec Kit planning, implementation, adversarial testing, the Control
Room, and release verification. It also states that GPT-5.6 performs structured
candidate extraction and semantic risk assessment after local sanitization,
while deterministic policy retains final authority. The Control Room visibly
labels the recorded semantic fixture used for the timed demo; this video is not
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

## Publication Record

The checksum-bound 109.733-second render is published as **Public**, assigned
to the existing `OpenAI Hack-a-thon` playlist, and below the three-minute
limit. The public URL is recorded consistently in this evidence file, the
submission draft, and the submission checklist. An unauthenticated `yt-dlp`
request independently verified public availability, the expected video ID and
title, a 1:50 duration, 1280x720 resolution, and the description's Codex,
GPT-5.6, repository, and Devpost references. Devpost accepted submission
`1095381` with this video on 2026-07-17 at 20:20:22 EDT.
