"""Anonymization of the output files. Port of ``-Anonymize`` in ``Get-GCPSizingInfo.ps1``.

Every value of a listed field is replaced by ``<Field>-<number>`` (``Project-00000``). The mapping is
shared by all files of a run, so a value that appears in several places, or in several fields, gets
one label everywhere and the files still join. Label columns are renamed
(``Label/Tag:Label/TagName-00000``) and their values replaced (``Label/TagValue-00000``). A key file
maps every label back to the real value.

Rules kept from the PowerShell script, checked against it with the same inputs:
  * values are matched without regard to case ("web" and "WEB" share a label);
  * an empty string is a value and is anonymized, a missing value (null) is left alone;
  * list values are anonymized item by item;
  * the label columns of a row are moved to its end;
  * the name of a label column is what follows ``Label/Tag:``, so it starts with a space, and the new
    column name has no space after ``Label/Tag:``.

Two rules are not kept:
  * PowerShell writes the counter as digits that repeat from the 11th distinct value of a field on
    (``Name-00000`` is given to the 1st and the 11th value, so 25 values come out as 15 labels). Here
    the labels are numbered one after the other, which is the same as PowerShell for the first ten
    values and unique beyond them.
  * PowerShell looks a value up by its text but stores it under the value itself, so for a value that
    is not text (the ``True`` or ``False`` of an attached disk's ``DiskEncryptionKey``, or a number
    added with ``-AnonymizeFields``) the lookup never finds it: every row gets a new label, and the key
    file keeps only the last one, so the others cannot be mapped back. Here one value has one label.

One rule is added (Python only, so the BigQuery and bucket files still join once anonymized): a
``gs://bucket/path`` in ``ExternalSourceUri`` keeps its shape. The bucket gets the label that
``BucketName`` gives the same bucket, and the path gets an ``ExternalSourceUri`` label. Any other
kind of source (Drive, Bigtable) is labelled whole, as before.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

# The fields the script anonymizes unless -NotAnonymizeFields lists them.
DEFAULT_FIELDS: tuple[str, ...] = (
    "Name",
    "Project",
    "VMName",
    "DiskName",
    "Id",
    "DiskEncryptionKey",
    "InstanceName",
    "DisplayName",
    "DatasetId",
    "TableId",
    "ExternalSourceUri",
    # Python only, for gce_storage_info (the script writes no bucket file). A bucket name is a
    # customer name, the connection ids name the project and the connection, and a key name
    # names the project, key ring and key.
    "BucketName",
    "BigQueryConnections",
    "DefaultKmsKeyName",
)

# The order the script anonymizes its lists in. The labels of a field are numbered in the order its
# values are first met, so the order of the files decides the numbers. ``gce_storage_info`` is not
# in the script and comes last, so it cannot change the numbering of the files that are.
FILE_ORDER: tuple[str, ...] = (
    "gce_vm_info",
    "gce_attached_disk_info",
    "gce_unattached_disk_info",
    "gce_cloudsql_info",
    "gce_spanner_info",
    "gce_bigquery_info",
    "gce_storage_info",
)

# The BigQuery column that holds ``gs://`` sources, and the field a bucket is labelled under.
URI_FIELD = "ExternalSourceUri"
BUCKET_FIELD = "BucketName"
_GS_URI = re.compile(r"gs://([^/\s;]+)(/.*)?", re.IGNORECASE)

TAG_PREFIX = "Label/Tag:"
TAG_KEY_FIELD = "Label/TagName"
TAG_VALUE_FIELD = "Label/TagValue"
KEY_FILE_PREFIX = "gcp_anonymized_keys_to_actual_values"


def _split_names(text: str) -> list[str]:
    return [name for name in (part.strip() for part in (text or "").split(",")) if name]


def _text(value: Any) -> str:
    """A value as PowerShell turns it into text: ``True``, ``100``, ``0.5``."""
    if isinstance(value, str):
        return value
    from csv_export import _format  # deferred: csv_export imports this module

    return _format(value)


class Anonymizer:
    """Holds the mapping and the counters of one run."""

    def __init__(self, extra_fields: Iterable[str] = (), not_fields: Iterable[str] = ()) -> None:
        not_fields = list(not_fields)
        fields = list(DEFAULT_FIELDS)
        for field in extra_fields:
            if field.casefold() not in {f.casefold() for f in fields}:
                fields.append(field)
        skip = {f.casefold() for f in not_fields}
        self.fields = {f.casefold() for f in fields} - skip
        self.anonymize_tags = "tags" not in skip
        self._labels: dict[str, str] = {}
        self._actual: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    @classmethod
    def from_options(
        cls, anonymize_fields: str = "", not_anonymize_fields: str = ""
    ) -> "Anonymizer":
        return cls(_split_names(anonymize_fields), _split_names(not_anonymize_fields))

    def _label(self, value: Any, field: str) -> str:
        text = _text(value)
        key = text.casefold()
        label = self._labels.get(key)
        if label is None:
            number = self._counters.get(field, 0)
            self._counters[field] = number + 1
            label = f"{field}-{number:05d}"
            self._labels[key] = label
            self._actual[key] = text
        return label

    def _label_uris(self, value: Any, field: str) -> str:
        """A source URI (or several joined by ``; ``) with each ``gs://`` bucket labelled as a bucket."""
        text = _text(value)
        parts = [part for part in (p.strip() for p in text.split(";")) if part]
        if not parts:
            return self._label(value, field)  # an empty string is a value, as everywhere else
        return "; ".join(self._label_uri(part, field) for part in parts)

    def _label_uri(self, uri: str, field: str) -> str:
        match = _GS_URI.fullmatch(uri)
        if match is None:
            return self._label(uri, field)
        bucket, path = match.group(1), match.group(2) or ""
        if BUCKET_FIELD.casefold() in self.fields:
            bucket = self._label(bucket, BUCKET_FIELD)
        if path in ("", "/"):
            return f"gs://{bucket}{path}"
        # The path is labelled with its leading "/", which no other value starts with, so it never
        # shares a label with a name from another column. The key file shows it with that slash.
        return f"gs://{bucket}/{self._label(path, field)}"

    def anonymize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """The row with its values replaced; label columns are renamed and moved to the end."""
        out: dict[str, Any] = {}
        tags: dict[str, Any] = {}
        for name, value in row.items():
            if name.casefold() in self.fields:
                if value is None:
                    out[name] = None
                elif isinstance(value, (list, tuple)):
                    out[name] = [self._label(item, name) for item in value]
                elif name.casefold() == URI_FIELD.casefold():
                    out[name] = self._label_uris(value, name)
                else:
                    out[name] = self._label(value, name)
            elif name.casefold().startswith(TAG_PREFIX.casefold()) and self.anonymize_tags:
                key = TAG_PREFIX + self._label(name[len(TAG_PREFIX) :], TAG_KEY_FIELD)
                tags[key] = None if value is None else self._label(value, TAG_VALUE_FIELD)
            else:
                out[name] = value
        out.update(tags)
        return out

    def key_rows(self) -> list[tuple[str, str]]:
        """(anonymized value, actual value) for every label handed out, by label."""
        rows = [(label, self._actual[key]) for key, label in self._labels.items()]
        return sorted(rows, key=lambda r: r[0].casefold())

    def key_file_text(self) -> str:
        """The key file as CSV: every value quoted, as PowerShell's Export-Csv writes it."""

        def quote(text: str) -> str:
            return '"' + text.replace('"', '""') + '"'

        lines = ['"AnonymizedValue","ActualValue"']
        lines += [f"{quote(a)},{quote(b)}" for a, b in self.key_rows()]
        return "\n".join(lines) + "\n"


def file_rank(prefix: str) -> int:
    """Position of a file in the order PowerShell anonymizes in (unknown files go last)."""
    try:
        return FILE_ORDER.index(prefix)
    except ValueError:
        return len(FILE_ORDER)


def anonymized_log_note() -> str:
    return (
        "Anonymized file; customer has original. "
        "Request customer to sanitize and provide output log if needed\n"
    )
