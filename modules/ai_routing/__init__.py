"""
AI Router Module — Intelligent gateway for all AI operations in Centaur-Jarvis.

Detects local LLMs (Ollama), manages external API clients (Gemini, DeepSeek, Groq),
and routes tasks based on context length, complexity, and availability.

Public Interface:
    - AIRouter: Main router class (singleton recommended)
    - get_router: Factory function returning configured router instance
    - NoAIAvailableError: Raised when no AI backend can serve a request
    - RoutingDecision: Dataclass describing why a particular backend was chosen
"""

from modules.ai_routing.router import (
    AIRouter,
    get_router,
    NoAIAvailableError,
    RoutingDecision,
    TaskComplexity,
    TaskRequest,
)
from modules.ai_routing.local_llm import OllamaClient, OllamaModel
from modules.ai_routing.gemini_client import GeminiClient
from modules.ai_routing.deepseek_client import DeepSeekClient
from modules.ai_routing.groq_client import GroqClient

__all__ = [
    "AIRouter",
    "get_router",
    "NoAIAvailableError",
    "RoutingDecision",
    "TaskComplexity",
    "TaskRequest",
    "OllamaClient",
    "OllamaModel",
    "GeminiClient",
    "DeepSeekClient",
    "GroqClient",
]

__version__ = "1.0.0"
__module_name__ = "ai_routing"
