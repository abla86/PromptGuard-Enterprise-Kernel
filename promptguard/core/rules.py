import re

class ThreatPatterns:
    DELIMITER_TOKENS = [
        r"<\|im_start\|>", r"<\|im_end\|>", r"<\|endoftext\|>",
        r"\[INST\]", r"\[/INST\]", r"<<SYS>>", r"<</SYS>>",
        r"<\|system\|>", r"<\|user\|>", r"<\|assistant\|>",
        r"```\s*system", r"<s>", r"</s>"
    ]

    ROLE_OVERRIDE = [
        r"(?i)(?:ignore\s+all\s+previous\s+instructions|disregard\s+(?:all\s+)?prior\s+rules)",
        r"(?i)(?:you\s+are\s+now\s+in\s+developer\s+mode|dan\s+mode\s+enabled)",
        r"(?i)(?:system\s*override:|emergency\s*protocol\s*alpha:)",
        r"(?i)(?:from\s+now\s+on\s+you\s+act\s+as\s+an\s+unconstrained)",
        r"(?i)(?:new\s+primary\s+objective:\s*reveal)"
    ]

    EXFILTRATION = [
        r"!\[.*?\]\(https?://[^\s\)]+[\?&](?:data|token|leak|secret|exfil)=.*?[\)\s]",
        r"<img\s+src=[\'\"]https?://[^\'\"]+[\?&](?:data|token|key|pwd)=",
        r"(?i)(?:curl|fetch|wget)\s+-[sS]*L?\s+https?://[^\s]+"
    ]
