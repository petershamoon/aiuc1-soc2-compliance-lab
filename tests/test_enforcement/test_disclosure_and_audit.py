# ---------------------------------------------------------------------------
# AIUC-1 SOC 2 Compliance Lab — Disclosure Injector & Audit Chain Tests
# ---------------------------------------------------------------------------
# Tests for the AI disclosure injection (E016) and the cryptographic
# audit chain (E015).
#
# Coverage:
#   - Disclosure injection into response envelopes
#   - Disclosure field structure and content
#   - Audit chain append-only integrity
#   - Chain hash verification
#   - Chain tamper detection
#   - Summary generation
# ---------------------------------------------------------------------------

import pytest
from functions.enforcement.disclosure import DisclosureInjector
from functions.enforcement.audit_chain import AuditChain, AuditEntry


class TestDisclosureInjector:
    """Test the AI disclosure injection (AIUC-1 E016)."""

    @pytest.fixture
    def injector(self):
        return DisclosureInjector()

    def test_disclosure_injected_into_envelope(self, injector):
        """Every envelope must receive an ai_disclosure field."""
        envelope = {"status": "success", "data": {"value": "test"}}
        result = injector.inject(envelope, "gap_analyzer")
        assert "ai_disclosure" in result

    def test_disclosure_field_structure(self, injector):
        """The ai_disclosure field must contain all required sub-fields."""
        envelope = {"status": "success", "data": {}}
        result = injector.inject(envelope, "gap_analyzer")
        disclosure = result["ai_disclosure"]

        assert disclosure["ai_generated"] is True
        assert "disclosure_text" in disclosure
        assert "disclosure_short" in disclosure
        assert "enforcement_layer_version" in disclosure
        assert disclosure["function_name"] == "gap_analyzer"
        assert "injected_at" in disclosure
        assert disclosure["aiuc1_control"] == "E016"

    def test_disclosure_includes_enforced_controls(self, injector):
        """Disclosure must include the list of enforced controls."""
        envelope = {"status": "success", "data": {}}
        controls = ["A006", "B009", "E015"]
        result = injector.inject(envelope, "test_fn", controls)
        assert result["ai_disclosure"]["enforced_controls"] == controls

    def test_disclosure_text_mentions_ai(self, injector):
        """Disclosure text must clearly state this is AI-generated output."""
        text = DisclosureInjector.get_disclosure_text()
        assert "AI" in text
        assert "human" in text.lower()

    def test_injection_count_tracks_calls(self, injector):
        """injection_count must increment with each injection."""
        assert injector.injection_count == 0
        injector.inject({"data": {}}, "fn1")
        assert injector.injection_count == 1
        injector.inject({"data": {}}, "fn2")
        assert injector.injection_count == 2

    def test_custom_disclosure_text(self):
        """Custom disclosure text must be used when provided."""
        custom = "Custom AI disclosure for testing."
        injector = DisclosureInjector(custom_text=custom)
        result = injector.inject({"data": {}}, "test_fn")
        assert result["ai_disclosure"]["disclosure_text"] == custom

    def test_version_is_set(self, injector):
        """VERSION class attribute must be set."""
        assert DisclosureInjector.VERSION
        assert isinstance(DisclosureInjector.VERSION, str)

    def test_disclosure_cannot_be_suppressed(self, injector):
        """Even if the envelope already has ai_disclosure, it must be overwritten."""
        envelope = {
            "status": "success",
            "data": {},
            "ai_disclosure": {"ai_generated": False, "note": "Fake"},
        }
        result = injector.inject(envelope, "test_fn")
        assert result["ai_disclosure"]["ai_generated"] is True
        assert "Fake" not in str(result["ai_disclosure"])


class TestAuditChain:
    """Test the cryptographic audit chain (AIUC-1 E015)."""

    @pytest.fixture
    def chain(self):
        return AuditChain()

    def test_empty_chain_verifies(self, chain):
        """An empty chain must verify as valid."""
        assert chain.verify() is True

    def test_genesis_hash(self, chain):
        """New chain must start with 'genesis' as head hash."""
        assert chain.head_hash == "genesis"

    def test_record_creates_entry(self, chain):
        """record() must create an AuditEntry with a hash."""
        entry = chain.record(
            function_name="gap_analyzer",
            action="sanitise",
            policy_id="ENF-001",
            applied=True,
            reason="Test sanitisation",
            aiuc1_controls=("A006", "B009"),
        )
        assert isinstance(entry, AuditEntry)
        assert entry.entry_hash  # Non-empty
        assert entry.sequence == 1

    def test_chain_links_entries(self, chain):
        """Each entry must reference the previous entry's hash."""
        e1 = chain.record(
            function_name="fn1", action="sanitise",
            policy_id="P1", applied=True, reason="First",
        )
        e2 = chain.record(
            function_name="fn2", action="block",
            policy_id="P2", applied=True, reason="Second",
        )
        assert e2.previous_hash == e1.entry_hash

    def test_chain_verifies_after_multiple_entries(self, chain):
        """Chain must verify after multiple entries."""
        for i in range(10):
            chain.record(
                function_name=f"fn_{i}",
                action="sanitise",
                policy_id=f"P-{i:03d}",
                applied=True,
                reason=f"Entry {i}",
                aiuc1_controls=("E015",),
            )
        assert chain.verify() is True
        assert chain.length == 10

    def test_head_hash_updates(self, chain):
        """head_hash must update after each record."""
        h0 = chain.head_hash
        chain.record(
            function_name="fn1", action="sanitise",
            policy_id="P1", applied=True, reason="First",
        )
        h1 = chain.head_hash
        assert h1 != h0

        chain.record(
            function_name="fn2", action="block",
            policy_id="P2", applied=True, reason="Second",
        )
        h2 = chain.head_hash
        assert h2 != h1

    def test_entry_hash_is_deterministic(self):
        """Same entry content must produce the same hash."""
        entry = AuditEntry(
            sequence=1,
            timestamp="2026-02-26T00:00:00+00:00",
            function_name="test",
            action="sanitise",
            policy_id="P1",
            applied=True,
            reason="Test",
            aiuc1_controls=("A006",),
            previous_hash="genesis",
        )
        h1 = entry.compute_hash()
        h2 = entry.compute_hash()
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex

    def test_summary_contains_required_fields(self, chain):
        """get_summary() must return all required fields."""
        chain.record(
            function_name="fn1", action="sanitise",
            policy_id="P1", applied=True, reason="Test",
            aiuc1_controls=("A006", "B009"),
        )
        summary = chain.get_summary()
        assert "chain_length" in summary
        assert "chain_head_hash" in summary
        assert "chain_verified" in summary
        assert "action_counts" in summary
        assert "controls_exercised" in summary
        assert summary["chain_length"] == 1
        assert summary["chain_verified"] is True

    def test_summary_action_counts(self, chain):
        """Summary must correctly count actions by type."""
        chain.record(function_name="fn1", action="sanitise",
                     policy_id="P1", applied=True, reason="A")
        chain.record(function_name="fn2", action="sanitise",
                     policy_id="P1", applied=True, reason="B")
        chain.record(function_name="fn3", action="block",
                     policy_id="P2", applied=True, reason="C")
        summary = chain.get_summary()
        assert summary["action_counts"]["sanitise"] == 2
        assert summary["action_counts"]["block"] == 1

    def test_summary_control_counts(self, chain):
        """Summary must correctly count controls exercised."""
        chain.record(function_name="fn1", action="sanitise",
                     policy_id="P1", applied=True, reason="A",
                     aiuc1_controls=("A006", "B009"))
        chain.record(function_name="fn2", action="block",
                     policy_id="P2", applied=True, reason="B",
                     aiuc1_controls=("B006", "A006"))
        summary = chain.get_summary()
        assert summary["controls_exercised"]["A006"] == 2
        assert summary["controls_exercised"]["B009"] == 1
        assert summary["controls_exercised"]["B006"] == 1

    def test_get_entries_for_function(self, chain):
        """get_entries_for_function() must filter by function name."""
        chain.record(function_name="fn1", action="sanitise",
                     policy_id="P1", applied=True, reason="A")
        chain.record(function_name="fn2", action="block",
                     policy_id="P2", applied=True, reason="B")
        chain.record(function_name="fn1", action="inject",
                     policy_id="P3", applied=True, reason="C")

        fn1_entries = chain.get_entries_for_function("fn1")
        assert len(fn1_entries) == 2
        assert all(e["action"] in ("sanitise", "inject") for e in fn1_entries)

    def test_chain_integrity_detection(self):
        """Tampering with the chain must be detectable.

        We simulate tampering by directly modifying the internal list.
        This tests that verify() catches the inconsistency.
        """
        chain = AuditChain()
        chain.record(function_name="fn1", action="sanitise",
                     policy_id="P1", applied=True, reason="First")
        chain.record(function_name="fn2", action="block",
                     policy_id="P2", applied=True, reason="Second")

        # Verify the chain is valid before tampering
        assert chain.verify() is True

        # Tamper: replace the first entry with a modified one
        original = chain._entries[0]
        tampered = AuditEntry(
            sequence=original.sequence,
            timestamp=original.timestamp,
            function_name="TAMPERED",
            action=original.action,
            policy_id=original.policy_id,
            applied=original.applied,
            reason=original.reason,
            aiuc1_controls=original.aiuc1_controls,
            details=original.details,
            previous_hash=original.previous_hash,
            entry_hash=original.entry_hash,  # Hash no longer matches content
        )
        chain._entries[0] = tampered

        # Chain should now fail verification
        assert chain.verify() is False
