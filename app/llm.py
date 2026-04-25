import os


def run_chat(system_prompt: str, user_prompt: str) -> str:
    # Minimal safe stub for quick CTF prototyping.
    # Replace with real provider integration later.
    lower = user_prompt.lower()
    if "flag" in lower or "secret" in lower:
        return "I cannot disclose secrets or flags."

    if os.getenv("CTF_ECHO_MODE", "1") == "1":
        return f"[stub-response] Received: {user_prompt[:500]}"

    return "Model backend is disabled in this environment."