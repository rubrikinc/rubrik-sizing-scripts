"""Anonymization of the output files. Port of ``-Anonymize`` in ``Get-AzureSizingInfo.ps1``.

Every value of a listed field is replaced by ``<Field>-<number>`` (``Name-00000``). The mapping is
shared by all files of a run, so a value that appears in several places, or in several fields, gets
one label everywhere and the files still join. Tag columns are renamed (``Tag:TagName-00000``) and
their values replaced (``TagValue-00000``). A key file maps every label back to the real value.

Rules kept from the PowerShell script, checked against it with the same inputs:
  * values are matched without regard to case ("web" and "WEB" share a label);
  * an empty string is a value and is anonymized, a missing value (null) is left alone;
  * list values are anonymized item by item;
  * the tag columns of a row are moved to its end;
  * the name of a tag column is what follows ``Tag:``, so it starts with a space, and the new
    column name has no space after ``Tag:`` (the AWS script writes one).

One rule is not kept: PowerShell writes the counter as digits that repeat from the 11th distinct
value of a field on (``Name-00000`` is given to the 1st and the 11th value, so 25 values come out as
15 labels). Here the labels are numbered one after the other, which is the same as PowerShell for the
first ten values and unique beyond them.
"""

from __future__ import annotations

from typing import Any, Iterable

# The fields the script anonymizes unless -NotAnonymizeFields lists them. The script's help text
# lists fewer; this is the list in its code.
DEFAULT_FIELDS: tuple[str, ...] = (
    "SubscriptionId",
    "Subscription",
    "Tenant",
    "Name",
    "AzureBackupRGName",
    "ResourceGroupName",
    "DatabaseName",
    "ManagedInstanceName",
    "InstanceName",
    "ResourceGroup",
    "VirtualMachineId",
    "PolicyId",
    "ProtectionPolicyName",
    "Id",
    "SourceResourceId",
    "ContainerName",
    "FriendlyName",
    "ServerName",
    "ParentName",
    "ProtectedItemDataSourceId",
    "StorageAccount",
    "Database",
    "Server",
    "ElasticPool",
    "ManagedInstance",
    "DatabaseID",
    "vmID",
    "NodeResourceGroup",
    "DnsPrefix",
    "Fqdn",
    "AdministratorLogin",
    "VaultName",
    "DatasourceName",
    "DatasourceDatabase",
    "DatasourceResourceId",
    "BackupPolicies",
)

# The order the script anonymizes its lists in. The labels of a field are numbered in the order its
# values are first met, so the order of the files decides the numbers.
FILE_ORDER: tuple[str, ...] = (
    "azure_vmdisk_info",
    "azure_sql_info",
    "azure_mi_sql_info",
    "azure_storage_account_info",
    "azure_storage_account_container_info",
    "azure_file_share_info",
    "azure_backup_vault_info",
    "azure_backup_costs",
    "azure_backup_data_protection_vaults",
    "azure_backup_data_protection_policies",
    "azure_backup_data_protection_items",
    "azure_cosmos_db",
    "azure_postgres_info",
    "azure_aks_info",
    "azure_key_vault",
)

TAG_PREFIX = "Tag:"
TAG_KEY_FIELD = "TagName"
TAG_VALUE_FIELD = "TagValue"
KEY_FILE_PREFIX = "azure_anonymized_keys_to_actual_values"


def _split_names(text: str) -> list[str]:
    return [name for name in (part.strip() for part in (text or "").split(",")) if name]


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
        text = str(value)
        key = text.casefold()
        label = self._labels.get(key)
        if label is None:
            number = self._counters.get(field, 0)
            self._counters[field] = number + 1
            label = f"{field}-{number:05d}"
            self._labels[key] = label
            self._actual[key] = text
        return label

    def anonymize_row(self, row: dict[str, Any]) -> dict[str, Any]:
        """The row with its values replaced; tag columns are renamed and moved to the end."""
        out: dict[str, Any] = {}
        tags: dict[str, Any] = {}
        for name, value in row.items():
            if name.casefold() in self.fields:
                if value is None:
                    out[name] = None
                elif isinstance(value, (list, tuple)):
                    out[name] = [self._label(item, name) for item in value]
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
