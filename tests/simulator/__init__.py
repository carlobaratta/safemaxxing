"""Deterministic macOS sensor/network simulator for CI.

Reproduces the *data* safemaxxing consumes on a Mac -- `log stream --style json` entries, the
socket table and pktap packets -- so the correlation heuristics can be exercised on Linux CI,
to the millisecond, without real hardware or personal data. `logs` renders synthetic log
output in the exact shape the real parser accepts; `fakes` holds the deterministic clock and
network sources; `scenarios` assembles both into named timelines and replays them through the
real `SensorEventParser` and `CorrelationEngine`.
"""
