"""RUG-449 synthetic local-record experiment; opaque placeholders are not encryption."""
import copy
import unittest


def update(record, changes):
    if record.get("schema_id") != "synthetic-service" or type(record.get("version")) is not int or record.get("version") != 1:
        raise ValueError("unsupported_schema")
    fields = record.get("fields")
    if not isinstance(fields, dict) or set(fields) != {"label", "opaque_value"}:
        raise ValueError("invalid_record")
    if not isinstance(changes, dict) or set(changes) - {"label", "opaque_value"}:
        raise ValueError("invalid_patch")
    candidate = copy.deepcopy(record)
    candidate["fields"].update(changes)
    for name, value in candidate["fields"].items():
        if not isinstance(value, str) or not value or len(value) > 256:
            raise ValueError("invalid_field")
    return candidate


def public_metadata(record):
    # Future authorization is a prerequisite; this is only a projection model.
    update(record, {})
    return {"schema_id": record["schema_id"], "version": record["version"]}


class SchemaExperimentTests(unittest.TestCase):
    def fixture(self):
        return {"schema_id": "synthetic-service", "version": 1,
                "fields": {"label": "synthetic-label", "opaque_value": "opaque-placeholder"}}

    def test_one_field_update_preserves_other_value_and_original(self):
        original = self.fixture()
        result = update(original, {"label": "new-label"})
        self.assertEqual(result["fields"]["opaque_value"], "opaque-placeholder")
        self.assertEqual(original["fields"]["label"], "synthetic-label")

    def test_unknown_schema_and_version_deny(self):
        for change in [{"schema_id": "other"}, {"version": 2}, {"version": True}]:
            with self.assertRaisesRegex(ValueError, "^unsupported_schema$"):
                update({**self.fixture(), **change}, {})

    def test_invalid_patch_does_not_mutate_source(self):
        original = self.fixture()
        before = copy.deepcopy(original)
        for changes in [{"unknown": "value"}, {"label": 1}, {"label": "x" * 257}, {"label": ""}]:
            with self.assertRaises(ValueError):
                update(original, changes)
            self.assertEqual(original, before)

    def test_projection_excludes_custom_fields_defaults_and_descriptions(self):
        record = {**self.fixture(), "description": "synthetic-private-description",
                  "defaults": {"label": "synthetic-private-default"}}
        self.assertEqual(public_metadata(record), {"schema_id": "synthetic-service", "version": 1})


if __name__ == "__main__":
    unittest.main()
