import unittest

from sentinel.observability import Metrics, request_id, route_name


class ObservabilityTests(unittest.TestCase):
    def test_request_ids_are_validated(self):
        self.assertEqual(request_id("request-123456"), "request-123456")
        generated = request_id("bad id with spaces")
        self.assertEqual(len(generated), 32)
        self.assertNotIn(" ", generated)

    def test_route_names_remove_entity_ids_and_queries(self):
        self.assertEqual(route_name("/api/test-runs/run_abc123?secret=value"), "/api/test-runs/:id")
        self.assertEqual(route_name("/health/ready"), "/health/ready")

    def test_prometheus_metrics_have_bounded_labels(self):
        metrics = Metrics()
        metrics.observe_request("GET", "/api/test-runs/:id", 200, 0.125)
        output = metrics.render({"queued": 2, "running": 1}).decode()
        self.assertIn('locus_http_requests_total{method="GET",route="/api/test-runs/:id",status="200"} 1', output)
        self.assertIn('locus_jobs{status="queued"} 2', output)
        self.assertNotIn("secret", output)


if __name__ == "__main__": unittest.main()
