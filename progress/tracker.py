import json
import uuid
from datetime import datetime, date, timedelta
from pathlib import Path

DATA_FILE = Path(__file__).parent.parent / "data" / "progress.json"


class ProgressTracker:
    def __init__(self):
        DATA_FILE.parent.mkdir(exist_ok=True)
        self._data = self._load()
        self._session_id = str(uuid.uuid4())[:8]
        self._session_start = datetime.now()
        self._activities: list[dict] = []

    def _load(self) -> dict:
        if DATA_FILE.exists():
            try:
                with open(DATA_FILE) as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                pass
        return {"sessions": []}

    def _save(self) -> None:
        duration = round((datetime.now() - self._session_start).total_seconds() / 60, 1)
        session = {
            "id": self._session_id,
            "date": date.today().isoformat(),
            "timestamp": self._session_start.isoformat(),
            "duration_minutes": duration,
            "activities": list(self._activities),
        }
        sessions = self._data["sessions"]
        for i, s in enumerate(sessions):
            if s["id"] == self._session_id:
                sessions[i] = session
                break
        else:
            sessions.append(session)
        try:
            with open(DATA_FILE, "w") as f:
                json.dump(self._data, f, indent=2)
        except OSError:
            pass

    def record_quiz(self, topic: str, score: int, total: int) -> None:
        pct = round(score / total * 100) if total > 0 else 0
        self._activities.append({
            "type": "quiz", "topic": topic,
            "score": score, "total": total, "percent": pct,
        })
        self._save()

    def record_iris(self, scenario: str, score: int) -> None:
        self._activities.append({"type": "iris", "scenario": scenario, "score": score})
        self._save()

    def record_activity(self, kind: str) -> None:
        self._activities.append({"type": kind})
        self._save()

    def get_stats(self) -> dict:
        sessions = self._data["sessions"]
        quizzes: list[dict] = []
        iris_sims: list[dict] = []
        dates: set[str] = set()

        for s in sessions:
            dates.add(s["date"])
            for a in s.get("activities", []):
                if a["type"] == "quiz":
                    quizzes.append(a)
                elif a["type"] == "iris":
                    iris_sims.append(a)

        by_topic: dict[str, list[int]] = {}
        for q in quizzes:
            by_topic.setdefault(q["topic"], []).append(q["percent"])
        topic_avg = {t: round(sum(v) / len(v)) for t, v in by_topic.items()}

        return {
            "total_sessions": len(sessions),
            "total_quizzes": len(quizzes),
            "avg_quiz_score": round(sum(q["percent"] for q in quizzes) / len(quizzes)) if quizzes else 0,
            "best_quiz_score": max((q["percent"] for q in quizzes), default=0),
            "total_iris": len(iris_sims),
            "avg_iris_score": round(sum(i["score"] for i in iris_sims) / len(iris_sims)) if iris_sims else 0,
            "streak_days": self._calc_streak(dates),
            "topic_stats": topic_avg,
            "recent_quizzes": list(reversed(quizzes[-5:])),
        }

    def _calc_streak(self, dates: set) -> int:
        if not dates:
            return 0
        date_set = {date.fromisoformat(d) for d in dates}
        check = date.today()
        streak = 0
        while check in date_set:
            streak += 1
            check -= timedelta(days=1)
        return streak
