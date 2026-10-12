"""Disclosure checks run before any result is published to model or browser."""
from __future__ import annotations
from .policy import AccessDenied

def check(rows: list[dict], *, customer_aggregate: bool, protected: bool) -> tuple[list[dict], list[str]]:
    notes: list[str] = []
    if customer_aggregate and not protected and (not rows or any(
            row["_population"] < 2 or row.get("_subjects", row["_population"]) < 2 for row in rows)):
        raise AccessDenied("Customer attribute aggregates require at least two distinct customers in every group.", "small_population")
    if protected:
        total = sum(row["_population"] for row in rows)
        if total < 10:
            raise AccessDenied("Protected-class reporting requires a population of at least ten customers.", "protected_population")
        small = [row for row in rows if row["_population"] < 3]
        if any(row["_population"] >= 3 and row.get("_subjects", row["_population"]) < 2 for row in rows):
            raise AccessDenied("This report would resolve a published cell to one person with multiple records.", "duplicate_subject")
        if small:
            # Categories present in the report have counts in [1,2]. Check the
            # completions consistent with all public cells and the known total.
            n, hidden_total = len(small), sum(row["_population"] for row in small)
            lower = max(1, hidden_total - 2 * (n - 1))
            upper = min(2, hidden_total - (n - 1))
            if n < 2 or len(rows) == 2 or lower >= upper:
                raise AccessDenied("This breakdown would allow suppressed counts to be inferred from the total.", "inferable_suppression")
            for row in small:
                for key in row:
                    if key.startswith(("count", "avg", "sum", "min", "max")):
                        row[key] = None
                row["suppressed"] = True
            notes.append("Small cells are suppressed; their exact counts and metrics are withheld.")
    released = [{k: v for k, v in row.items() if k not in {"_population", "_subjects"}} for row in rows]
    return released, notes
