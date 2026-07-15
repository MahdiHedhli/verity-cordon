# Verity Cordon Detector Plugin Example

This directory is a small, local-only reference package for the
`verity_cordon.detectors` entry-point boundary. It is not published and is not
required by the core package.

The plugin exposes one side-effect-free detector:

- Entry point: `demo-synthetic-sink`
- Detector ID: `demo-synthetic-sink`
- Detector version: `1.0.0`
- Match: the exact synthetic marker `demo_artifact_sink`

The narrow marker is intentional. This example demonstrates discovery,
versioning, and safe result construction; it is not presented as a general
security detector. It performs no network, filesystem, subprocess, environment,
or logging operations.

## Install locally

From the Verity Cordon repository root, inside an isolated environment:

```bash
python -m pip install -e .
python -m pip install -e examples/detector-plugin
```

An entry-point host can discover it with:

```python
from importlib.metadata import entry_points

for entry_point in entry_points(group="verity_cordon.detectors"):
    detector_factory = entry_point.load()
    detector = detector_factory()
```

The host remains responsible for rejecting duplicate detector IDs, isolating
failures, applying timeouts, and giving deterministic policy final authority.

## Test

From the repository root:

```bash
PYTHONPATH=src:examples/detector-plugin/src python -m pytest examples/detector-plugin/tests
```
