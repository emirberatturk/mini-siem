"""Alert durum makinesi: hangi durumdan hangisine geçilebilir, hangisinde not zorunlu."""

from enum import StrEnum


class AlertStatus(StrEnum):
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


S = AlertStatus
TRANSITIONS: dict[AlertStatus, set[AlertStatus]] = {
    S.NEW: {S.INVESTIGATING, S.FALSE_POSITIVE},
    S.INVESTIGATING: {S.CONFIRMED, S.FALSE_POSITIVE, S.RESOLVED},
    S.CONFIRMED: {S.RESOLVED},
    S.FALSE_POSITIVE: {S.INVESTIGATING},  # yeniden açma
    S.RESOLVED: {S.INVESTIGATING},  # yeniden açma
}

# Bu durumlara geçerken gerekçe yazılmalı (denetim izi)
NOTE_REQUIRED = {S.FALSE_POSITIVE, S.RESOLVED}


class TransitionError(ValueError):
    pass


def check_transition(current: str, target: AlertStatus, note: str) -> None:
    cur = AlertStatus(current)
    if target not in TRANSITIONS[cur]:
        allowed = ", ".join(sorted(TRANSITIONS[cur])) or "yok"
        raise TransitionError(
            f"'{cur}' durumundan '{target}' durumuna geçilemez (izinli: {allowed})"
        )
    reopening = cur in (S.FALSE_POSITIVE, S.RESOLVED)
    if (target in NOTE_REQUIRED or reopening) and not note.strip():
        raise TransitionError("Bu durum değişikliği için bir not (gerekçe) yazılmalı")
