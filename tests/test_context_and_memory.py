"""Unit tests for Category 2: Context & Memory (20 pts).

Verifies:
- 2.1 Robust System Instructions (constitution with persona, domain knowledge, constraints)
- 2.2 History Compaction (ADK EventsCompactionConfig, ContextCacheConfig, sliding window)
- 2.3 Persistent Session State (SQLite durable multi-turn state + semantic vector retrieval)
- 2.4 Async Memory Operations (non-blocking background asyncio queue consolidation)
"""

from __future__ import annotations

from pathlib import Path
import tempfile
import time
import unittest

from sentinel_sre_agent.agent import app
from sentinel_sre_agent.memory import (
    AsyncMemoryConsolidator,
    PersistentSessionAndVectorStore,
    TokenBudgetHistoryCompactor,
)
from sentinel_sre_agent.prompts import (
    COORDINATOR_INSTRUCTION,
    SENTINEL_CONSTITUTION_CORE,
)


class TestContextAndMemory(unittest.IsolatedAsyncioTestCase):
    def test_system_constitution_defines_persona_domain_and_hard_constraints(self) -> None:
        self.assertIn("<persona>", SENTINEL_CONSTITUTION_CORE)
        self.assertIn("<domain_knowledge>", SENTINEL_CONSTITUTION_CORE)
        self.assertIn("<hard_constraints>", SENTINEL_CONSTITUTION_CORE)
        self.assertIn("<output_contract>", SENTINEL_CONSTITUTION_CORE)
        self.assertIn("<role_mandate", COORDINATOR_INSTRUCTION)

    def test_adk_compaction_context_cache_and_sliding_window_compactor(self) -> None:
        self.assertIsNotNone(app.events_compaction_config)
        self.assertEqual(app.events_compaction_config.compaction_interval, 4)
        self.assertEqual(app.events_compaction_config.overlap_size, 1)

        self.assertIsNotNone(app.context_cache_config)
        self.assertEqual(app.context_cache_config.min_tokens, 2048)

        compactor = TokenBudgetHistoryCompactor(max_context_tokens=220, retained_recent_turns=2)
        bloated_history = [
            {"role": "system", "content": "Constitution header."},
            *[
                {
                    "role": "user" if idx % 2 == 0 else "assistant",
                    "content": f"Historical diagnostic turn #{idx}: " + ("telemetry " * 18),
                }
                for idx in range(10)
            ],
        ]
        result = compactor.compact(bloated_history)
        self.assertTrue(result.summary_injected)
        self.assertGreater(result.evicted_turn_count, 0)
        self.assertLess(result.compacted_token_estimate, result.original_token_estimate)
        self.assertEqual(result.messages[0]["role"], "system")
        self.assertIn("COMPACTED_SESSION_HISTORY_SUMMARY", result.messages[1]["content"])

    async def test_persistent_session_db_and_non_blocking_async_memory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_file = Path(tmp_dir) / "persistent_sessions.db"
            store = PersistentSessionAndVectorStore(db_file)
            store.append_turn(
                session_id="sess-42",
                user_id="alice",
                role="user",
                content="Contact oncall jane.doe@example.com for checkout-api canary rollback.",
            )
            store.upsert_session_state("sess-42", "active_incident", {"service": "checkout-api"})

            # Re-open fresh instance against the same SQLite file to prove durability across turns
            reopened = PersistentSessionAndVectorStore(db_file)
            turns = reopened.get_session_history("sess-42")
            self.assertEqual(len(turns), 1)
            # PII email is automatically redacted prior to storage!
            self.assertNotIn("jane.doe@example.com", turns[0]["content"])
            self.assertIn("[REDACTED_EMAIL]", turns[0]["content"])
            self.assertEqual(
                reopened.get_session_state("sess-42")["active_incident"]["service"],
                "checkout-api",
            )

            # Verify non-blocking async memory consolidation
            consolidator = AsyncMemoryConsolidator(reopened)
            t0 = time.perf_counter()
            consolidator.schedule_consolidation(
                user_id="alice",
                session_id="sess-42",
                transcript_turns=turns,
                incident_tags=["checkout-api", "RB-104"],
            )
            enqueue_ms = (time.perf_counter() - t0) * 1000.0
            self.assertLess(enqueue_ms, 50.0, "Async consolidation enqueue blocked caller!")

            await consolidator.flush()
            self.assertEqual(consolidator.processed_count, 1)

            recalled = reopened.search_semantic_memories(
                user_id="alice",
                query="checkout-api canary rollback",
                top_k=1,
            )
            self.assertEqual(len(recalled), 1)
            self.assertGreater(recalled[0]["similarity"], 0.2)
            await consolidator.shutdown()


if __name__ == "__main__":
    unittest.main()
