import unittest

from sentinel.classifier import GaussianNB
from sentinel.models import FAILURE_TYPES
from sentinel.simulator import IncidentLab, training_data


class ClassifierTests(unittest.TestCase):
    def test_probabilities_sum_to_one(self):
        rows, labels = training_data(samples_per_class=10)
        classifier = GaussianNB().fit(rows, labels)
        probabilities = classifier.predict_proba(rows[0])
        self.assertAlmostEqual(sum(probabilities.values()), 1.0)

    def test_classifier_separates_training_scenarios(self):
        train_rows, train_labels = training_data(seed=1, samples_per_class=80)
        test_rows, test_labels = training_data(seed=2, samples_per_class=20)
        classifier = GaussianNB().fit(train_rows, train_labels)
        predictions = [
            max(classifier.predict_proba(row), key=classifier.predict_proba(row).get)
            for row in test_rows
        ]
        accuracy = sum(a == b for a, b in zip(predictions, test_labels)) / len(test_labels)
        self.assertGreater(accuracy, 0.9)

    def test_lab_generates_every_scenario(self):
        lab = IncidentLab()
        for scenario in FAILURE_TYPES:
            trace = lab.run(scenario, seed=42)
            self.assertEqual(trace.scenario, scenario)
            self.assertIn("predicted", trace.diagnosis)
            self.assertEqual(len(trace.spans), 3)


if __name__ == "__main__":
    unittest.main()
