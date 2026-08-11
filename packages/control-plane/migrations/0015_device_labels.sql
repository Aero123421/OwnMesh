-- Display-only device labels. Labels are never consulted for authorization.
ALTER TABLE devices
  ADD COLUMN labels_json TEXT NOT NULL DEFAULT '[]'
  CHECK (
    json_valid(labels_json)
    AND json_type(labels_json) = 'array'
    AND length(labels_json) <= 4096
  );
