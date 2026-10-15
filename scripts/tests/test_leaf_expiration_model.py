"""Test-only RUG-269 strict candidate. Never imported by runtime code."""
import unittest


def decision(start, end, now, *, clock_healthy=True, prior_time=None):
    """Synthetic integer UTC seconds; health is an input, not established here."""
    if not all(type(value) is int for value in (start, end, now)) or start >= end:
        return "invalid_validity"
    if not clock_healthy or (prior_time is not None and now < prior_time):
        return "clock_untrusted"
    if now < start:
        return "not_yet_valid"
    if now >= end:
        return "expired"
    return "allow"


class ExpirationCandidateTests(unittest.TestCase):
    def test_boundary_matrix(self):
        for now, expected in [(99, "not_yet_valid"), (100, "allow"),
                              (150, "allow"), (199, "allow"),
                              (200, "expired"), (201, "expired")]:
            with self.subTest(now=now):
                self.assertEqual(decision(100, 200, now), expected)

    def test_invalid_windows_and_precision(self):
        for start, end, now in [(100, 100, 100), (200, 100, 150),
                                (True, 200, 150), (100, 200, 150.5)]:
            self.assertEqual(decision(start, end, now), "invalid_validity")

    def test_unknown_time_and_observed_rollback(self):
        self.assertEqual(decision(100, 200, 150, clock_healthy=False), "clock_untrusted")
        self.assertEqual(decision(100, 200, 150, prior_time=151), "clock_untrusted")

    def test_cache_does_not_cache_allow(self):
        parsed_window = (100, 200)
        self.assertEqual(decision(*parsed_window, 199), "allow")
        self.assertEqual(decision(*parsed_window, 200), "expired")

    def test_restart_requires_time_health_input(self):
        restored_window = (100, 200)
        self.assertEqual(decision(*restored_window, 201), "expired")
        self.assertEqual(decision(*restored_window, 150, clock_healthy=False), "clock_untrusted")


if __name__ == "__main__":
    unittest.main()
