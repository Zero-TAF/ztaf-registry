"""ztaf-registry: the Zero-TAF registry reference (agents, mandates,
capability provenance, signed revocation status lists). Reference only; the
normative revocation semantics live in ztaf-spec (mandate format document
section 5)."""

from .registry import FileRegistry, RegistryError

__version__ = "0.1.0"
