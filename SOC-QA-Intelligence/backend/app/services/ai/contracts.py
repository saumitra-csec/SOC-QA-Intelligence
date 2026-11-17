"""
Future Module Interface — Explainable AI Investigation Quality Assessment Engine.
Vendor-agnostic provider abstraction supporting hosted LLM APIs and local Ollama models.
Disabled by default until explicitly configured. Includes prompt-injection sanitization
over untrusted emails, command lines, and logs.
"""
from abc import ABC, abstractmethod
from typing import Any, Dict, List
from backend.app.core.config import settings
from backend.app.core.security import sanitize_untrusted_text_for_ai

ASSESSMENT_CATEGORIES = [
    "investigation_completeness",
    "evidence_sufficiency",
    "decision_justification",
    "escalation_quality",
    "documentation_quality",
    "closure_quality",
]


class ExplainableAIProviderContract(ABC):
    """Vendor-independent interface for evidence-grounded SOC quality assessment."""

    @abstractmethod
    def get_provider_status(self) -> Dict[str, Any]:
        """Returns configuration status, active model, and prompt version."""

    @abstractmethod
    def prepare_sanitized_case_context(
        self, case_id: str, excerpts: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        """Sanitizes untrusted log/email excerpts against prompt injection before LLM dispatch."""

    @abstractmethod
    def request_structured_assessment(self, case_id: str) -> Dict[str, Any]:
        """Requests a structured JSON quality assessment requiring human validation."""


class ConfigurableAIService(ExplainableAIProviderContract):
    def get_provider_status(self) -> Dict[str, Any]:
        return {
            "ai_module_enabled": settings.ai_module_enabled,
            "configured_provider": settings.ai_provider,
            "configured_model": settings.ai_model_name,
            "prompt_version": settings.ai_prompt_version,
            "supported_providers": [
                "openai_compatible_api",
                "anthropic_claude_api",
                "local_ollama_llm",
                "local_vllm_server",
            ],
            "assessment_dimensions": ASSESSMENT_CATEGORIES,
            "independence_guarantee": "Decoupled from PM4Py process-mining engine",
            "human_validation_policy": "All findings default to PENDING_HUMAN_REVIEW",
        }

    def prepare_sanitized_case_context(
        self, case_id: str, excerpts: List[Dict[str, str]]
    ) -> Dict[str, Any]:
        sanitized_items = []
        injection_alerts = 0
        for item in excerpts:
            res = sanitize_untrusted_text_for_ai(item.get("text", ""))
            if res["injection_detected"]:
                injection_alerts += 1
            sanitized_items.append(
                {
                    "record_id": item.get("record_id"),
                    "sanitized_text": res["sanitized_text"],
                    "injection_detected": res["injection_detected"],
                    "matched_patterns": res["matches"],
                }
            )
        return {
            "case_id": case_id,
            "prompt_version": settings.ai_prompt_version,
            "total_excerpts": len(excerpts),
            "prompt_injection_alerts": injection_alerts,
            "sanitized_excerpts": sanitized_items,
        }

    def request_structured_assessment(self, case_id: str) -> Dict[str, Any]:
        if not settings.ai_module_enabled or settings.ai_provider == "disabled":
            return {
                "status": "AI_PROVIDER_DISABLED",
                "case_id": case_id,
                "findings": [],
                "message": (
                    "AI integration is disabled by default per research architecture requirements. "
                    "Configure AI_MODULE_ENABLED=true and a valid provider in .env after process models and event logs are validated."
                ),
            }
        return {"status": "READY_FOR_PROVIDER_DISPATCH", "case_id": case_id, "findings": []}


ai_service = ConfigurableAIService()
