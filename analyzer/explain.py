"""Ask Gemini to explain a Suricata alert group in plain English.

Uses structured outputs (response_schema + a Pydantic schema) so the
response is always valid, typed JSON -- no regex-scraping the model's
prose for a severity label.
"""

from __future__ import annotations

import json
import os
from typing import Literal

from google import genai
from google.genai import types
from pydantic import BaseModel, Field

MODEL = os.environ.get("GEMINI_MODEL", "gemini-flash-latest")
EFFORT = os.environ.get("GEMINI_EFFORT", "medium")

# Gemini has no named effort tiers -- it takes a thinking-token budget
# instead. These values are within the valid range for both
# gemini-2.5-flash (0-24576) and gemini-2.5-pro (128-32768); -1 means "let
# the model decide how much to think".
THINKING_BUDGETS = {"low": 1024, "medium": -1, "high": 24576}

SYSTEM_PROMPT = """\
You are a security analyst assistant. You explain Suricata IDS alerts so that
both a security analyst and a non-technical stakeholder (e.g. an IT manager)
can understand what happened and how worried to be.

You will be given one alert "group" -- a Suricata signature that fired one
or more times for the same source/destination pair, plus one or two raw
sample events (JSON) for context.

Ground every claim in the data you were given. If the signature is a known
false-positive-prone or informational rule, say so plainly rather than
inflating the severity. If you are not confident, say so in `confidence`
rather than guessing.
"""


class AlertExplanation(BaseModel):
    severity: Literal["informational", "low", "medium", "high", "critical"] = Field(
        description="Your assessed severity, which may differ from Suricata's "
        "own rule severity if the context changes how worrying this is."
    )
    summary: str = Field(
        description="2-4 sentences, plain English, no jargon. What happened, "
        "in terms a non-technical reader can understand."
    )
    technical_detail: str = Field(
        description="1-3 sentences for a security analyst: what the signature "
        "detects, and what in the sample data specifically matched."
    )
    recommended_action: str = Field(
        description="One concrete next step. E.g. 'No action needed -- this is "
        "expected background traffic' or 'Isolate this host and inspect the "
        "process making this connection.'"
    )
    confidence: Literal["low", "medium", "high"] = Field(
        description="How confident you are in this assessment given the "
        "available context."
    )


def _build_user_prompt(group) -> str:
    samples = json.dumps(group.sample_events, indent=2, default=str)
    return f"""\
Alert signature: {group.signature} (sid {group.signature_id})
Suricata category: {group.category}
Suricata rule severity (1=high ... 3=low): {group.suricata_severity}

Source: {group.src_ip}
Destination: {group.dest_ip}:{group.dest_port} ({group.dest_hostname or "no hostname resolved"})
Protocol: {group.proto} / app-layer: {group.app_proto or "unknown"}

This exact signature fired {group.count} time(s) between {group.first_seen} and {group.last_seen}.

Sample raw event(s):
{samples}
"""


def explain_group(client: genai.Client, group) -> dict:
    response = client.models.generate_content(
        model=MODEL,
        contents=_build_user_prompt(group),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM_PROMPT,
            # Thinking tokens are drawn from the same max_output_tokens budget
            # as the answer, so this needs headroom above the thinking budget
            # below or the JSON gets truncated mid-object and response.parsed
            # comes back None.
            max_output_tokens=4096,
            response_mime_type="application/json",
            response_schema=AlertExplanation,
            thinking_config=types.ThinkingConfig(
                thinking_budget=THINKING_BUDGETS.get(EFFORT, -1)
            ),
        ),
    )
    if response.parsed is None:
        raise ValueError(
            f"Gemini returned no parsed output (finish_reason="
            f"{response.candidates[0].finish_reason})"
        )
    return response.parsed.model_dump()
