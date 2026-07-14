OWASP_BY_SCANNER: dict[str, list[str]] = {
    "PromptInjectionScanner": ["LLM01"],
    "SecretScanner": ["LLM02"],
    "PIIScanner": ["LLM02"],
    "URLScanner": ["LLM05"],
    "MalwareURLScanner": ["LLM05", "LLM08"],
}


def categories_for(scanner: str) -> list[str]:
    return OWASP_BY_SCANNER.get(scanner, [])
