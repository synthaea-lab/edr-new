# server/ingest

Agent-facing ingestion service: terminates agent mTLS connections, validates and stores
uploaded events and detections, and tracks agent heartbeats (silence is a detection).
