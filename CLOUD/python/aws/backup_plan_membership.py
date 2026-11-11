"""Which AWS Backup plans select a resource: a port of PowerShell's plan matching.

``Get-AWSSizingInfo.ps1`` (``Get-AWSBackupPlanInventory``, ``Test-RowTagConditionMatch`` and
``Test-RowMatchesSelection``) decides ``BackupPlans`` and ``InBackupPlan`` for every workload row
from the plans' selections, not from what AWS Backup protects. This module does the same, quirks
included, with no boto3 and no I/O.

Plans are dicts shaped like the serialized discovery JSON (``BackupPlan`` with its
``BackupSelection`` entries). Rows are ``RowView``s built by the caller from the CSV rows' tag
columns. PowerShell's rules, as ported:

* Plans are processed per (account, region) group in scan order, in list order, selection by
  selection. Per selection: explicit ``Resources`` ARNs, then tag/condition criteria, then
  ``NotResources``.
* Explicit and tag matching only look at rows of the plan's own account and region.
  ``NotResources`` is not scoped: PowerShell's lists grow while it scans, so a ``NotResources``
  ARN strips the plan from rows of this group and of every earlier group, never later ones.
* Explicit ARNs are parsed per resource type with PowerShell's own splitting, so an index that is
  missing is ``None`` (PowerShell's ``$null``). See ``_explicit_positions``.
* Tag criteria: ``ListOfTags`` (``STRINGEQUALS`` only) are OR-ed, ``StringEquals``/``StringLike``
  are AND-ed, ``StringNotEquals``/``StringNotLike`` disqualify. A selection with no criteria
  matches nothing by tags. Everything is compared case-insensitively.

Matching uses an inverted index per group, so many tag selections stay fast; ``row_matches`` is
the plain per-row definition of the same rules, which the tests check against PowerShell itself.
"""

from __future__ import annotations

import logging
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import AbstractSet, Iterable, Mapping, Optional, Sequence

log = logging.getLogger(__name__)

# Row kinds a plan can select. The CSV rows of unattached EBS volumes are not here: PowerShell
# matches against raw SDK objects for them, which never match, so they always stay "not in a plan".
KINDS = (
    "ec2_instance",
    "ebs_attached",
    "rds",
    "efs",
    "fsx_volume",
    "fsx_filesystem",
    "s3",
    "dynamodb",
    "s3_table",
)


@dataclass(frozen=True)
class RowView:
    """What the matcher needs of one workload row.

    ``ids`` holds the identifying values by PowerShell's column names: ``InstanceId``,
    ``VolumeId``, ``DBInstanceIdentifier``, ``FileSystemId`` (also with ``VolumeId`` for FSx
    volumes), ``BucketName``, ``TableBucketName``. ``tag_columns`` are the row's ``Tag: <key>``
    columns exactly as the CSV has them (empty for DynamoDB, which has no tag columns).
    """

    kind: str
    account_id: str
    region: str
    ids: Mapping[str, str]
    resource_arn: str
    tag_columns: Mapping[str, Optional[str]]


@dataclass
class Membership:
    plan_names: list[str]
    in_plan: bool


# ── tag and condition rules (Test-RowTagConditionMatch / Test-RowMatchesSelection) ───────────────


@dataclass(frozen=True)
class Cond:
    op: str  # "Equals" or "Like", PowerShell's own names
    key: str
    value: str


@dataclass(frozen=True)
class Criteria:
    or_tags: tuple[Cond, ...] = ()
    and_conds: tuple[Cond, ...] = ()
    not_conds: tuple[Cond, ...] = ()

    def any(self) -> bool:
        return bool(self.or_tags or self.and_conds or self.not_conds)


_RESOURCE_TAG_PREFIX = re.compile(r"aws:resourcetag/(.+)$", re.IGNORECASE)  # `.` skips newlines
_NON_ALNUM = re.compile(r"[^a-zA-Z0-9]")


def tag_column_name(key: Optional[str]) -> str:
    """The lower-cased ``tag: <key>`` column a condition key looks at.

    The ``aws:ResourceTag/`` prefix of a ``Conditions`` key is removed (ListOfTags keys are bare),
    then every character outside ``[a-zA-Z0-9]`` becomes ``_``, as the CSV columns are built.
    A null key is the empty string.
    """
    raw = key or ""
    found = _RESOURCE_TAG_PREFIX.match(raw)
    name = found.group(1) if found else raw
    return "tag: " + _NON_ALNUM.sub("_", name).lower()


def tag_index(tag_columns: Mapping[str, Optional[str]]) -> dict[str, Optional[str]]:
    """Columns by lower-cased name. PowerShell adds tags with ``Add-Member -Force`` and member
    names ignore case, so columns that differ only by case collapse and the last one wins."""
    index: dict[str, Optional[str]] = {}
    for column, value in tag_columns.items():
        index[column.lower()] = value
    return index


def _translate_wildcard(pattern: str) -> str:
    """A PowerShell wildcard as a regular expression: ``*``, ``?``, ``[set]`` (literal members and
    ``a-z`` ranges; ``!`` and ``^`` are plain members, not negation) and a backtick to escape.
    An unclosed or empty set is invalid (PowerShell throws)."""
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "`":
            i += 1
            out.append(re.escape(pattern[i] if i < n else "`"))
        elif c == "*":
            out.append(".*")
        elif c == "?":
            out.append(".")
        elif c == "[":
            j, members = i + 1, []
            while j < n and pattern[j] != "]":
                if pattern[j] == "`" and j + 1 < n:
                    members.append(re.escape(pattern[j + 1]))
                    j += 2
                elif j + 2 < n and pattern[j + 1] == "-" and pattern[j + 2] != "]":
                    members.append(f"{re.escape(pattern[j])}-{re.escape(pattern[j + 2])}")
                    j += 3
                else:
                    members.append(re.escape(pattern[j]))
                    j += 1
            if j >= n or not members:
                raise ValueError(f"invalid wildcard pattern {pattern!r}")
            out.append("[" + "".join(members) + "]")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


_LIKE_CACHE: dict[str, Optional["re.Pattern[str]"]] = {}


def _like_regex(pattern: str) -> Optional["re.Pattern[str]"]:
    """The compiled pattern, or None for an invalid one.

    PowerShell throws on an invalid pattern, which stops the rest of the region's plans; here it
    matches nothing and is logged once.
    """
    if pattern not in _LIKE_CACHE:
        try:
            compiled = re.compile(_translate_wildcard(pattern), re.IGNORECASE | re.DOTALL)
        except (ValueError, re.error):
            log.warning("Backup selection wildcard %r is invalid; it matches nothing", pattern)
            compiled = None
        _LIKE_CACHE[pattern] = compiled
    return _LIKE_CACHE[pattern]


def ps_like(value: str, pattern: str) -> bool:
    """PowerShell's ``-like``: case-insensitive, whole string."""
    compiled = _like_regex(pattern)
    return bool(compiled and compiled.fullmatch(value))


def cond_matches(index: Mapping[str, Optional[str]], cond: Cond) -> bool:
    """``Test-RowTagConditionMatch``. A missing column or a null value never matches."""
    value = index.get(tag_column_name(cond.key))
    if value is None:
        return False
    if cond.op == "Equals":
        return str(value).lower() == cond.value.lower()
    return ps_like(str(value), cond.value)


def row_matches(index: Mapping[str, Optional[str]], criteria: Criteria) -> bool:
    """``Test-RowMatchesSelection``: the OR group, every AND condition and no negation."""
    if not criteria.any():
        return False
    if criteria.or_tags and not any(cond_matches(index, c) for c in criteria.or_tags):
        return False
    if not all(cond_matches(index, c) for c in criteria.and_conds):
        return False
    return not any(cond_matches(index, c) for c in criteria.not_conds)


def _conds(entries: Optional[Iterable[Optional[Mapping]]], op: str) -> list[Cond]:
    return [
        Cond(op, str(e.get("ConditionKey") or ""), str(e.get("ConditionValue") or ""))
        for e in entries or []
        if e is not None
    ]


def criteria_from_selection(selection: Mapping) -> Criteria:
    """The tag criteria of one selection dict, as PowerShell collects them."""
    # ListOfTags: only STRINGEQUALS entries count, whatever else the entry says.
    or_tags = _conds(
        [
            t
            for t in selection.get("list_of_tags") or []
            if t is not None and str(t.get("ConditionType") or "").upper() == "STRINGEQUALS"
        ],
        "Equals",
    )
    return Criteria(
        or_tags=tuple(or_tags),
        and_conds=tuple(
            _conds(selection.get("string_equals"), "Equals")
            + _conds(selection.get("string_like"), "Like")
        ),
        not_conds=tuple(
            _conds(selection.get("string_not_equals"), "Equals")
            + _conds(selection.get("string_not_like"), "Like")
        ),
    )


# ── explicit ARNs ─────────────────────────────────────────────────────────────────────────────


def _part(parts: Sequence[str], index: int) -> Optional[str]:
    """``parts[index]``, or None where PowerShell's out-of-range index gives ``$null``."""
    return parts[index] if 0 <= index < len(parts) else None


def _id_key(row: RowView):
    """The lower-cased identity explicit ARNs are compared with, per kind (None: not matchable)."""
    ids = row.ids
    if row.kind == "fsx_volume":
        fs, vol = ids.get("FileSystemId"), ids.get("VolumeId")
        return (fs.lower(), vol.lower()) if fs is not None and vol is not None else None
    field = {
        "ec2_instance": "InstanceId",
        "ebs_attached": "VolumeId",
        "rds": "DBInstanceIdentifier",
        "efs": "FileSystemId",
        "s3": "BucketName",
        "s3_table": "TableBucketName",
    }.get(row.kind)
    value = ids.get(field) if field else None
    return value.lower() if value is not None else None


_EMPTY: frozenset = frozenset()


class _Group:
    """The rows of one (account, region), indexed for explicit ARNs and tag criteria."""

    def __init__(self, positions: list[int], rows: Sequence[RowView]) -> None:
        self.positions = positions
        self.all = frozenset(positions)
        self.by_kind: dict[str, list[int]] = defaultdict(list)
        self.by_id: dict[tuple, list[int]] = defaultdict(list)
        # tag column -> lower-cased value -> rows that have that value (a null value is absent)
        self.tags: dict[str, dict[str, set[int]]] = defaultdict(lambda: defaultdict(set))
        self._hits: dict[tuple, AbstractSet[int]] = {}
        for pos in positions:
            row = rows[pos]
            self.by_kind[row.kind].append(pos)
            key = _id_key(row)
            if key is not None:
                self.by_id[(row.kind, key)].append(pos)
            for column, value in tag_index(row.tag_columns).items():
                if value is not None:
                    self.tags[column][str(value).lower()].add(pos)

    def of_kind(self, kind: str) -> list[int]:
        return self.by_kind.get(kind, [])

    def with_id(self, kind: str, ident: Optional[str], wildcard: bool) -> list[int]:
        """Rows of ``kind`` whose id equals ``ident``; ``*`` matches all where PowerShell allows."""
        if ident is None:
            return []
        if wildcard and ident == "*":
            return self.of_kind(kind)
        return self.by_id.get((kind, ident.lower()), [])

    def hits(self, cond: Cond) -> AbstractSet[int]:
        column = tag_column_name(cond.key)
        cache_key = (cond.op, column, cond.value if cond.op == "Like" else cond.value.lower())
        cached = self._hits.get(cache_key)
        if cached is not None:
            return cached
        values = self.tags.get(column)
        result: AbstractSet[int]
        if not values:
            result = _EMPTY
        elif cond.op == "Equals":
            result = values.get(cond.value.lower(), _EMPTY)
        else:
            compiled = _like_regex(cond.value)
            found: set[int] = set()
            if compiled is not None:
                for value, positions in values.items():
                    if compiled.fullmatch(value):
                        found |= positions
            result = found
        self._hits[cache_key] = result
        return result

    def matched(self, criteria: Criteria) -> AbstractSet[int]:
        """Rows matching ``row_matches`` for ``criteria``, from the index (negation is the
        complement of its hits). The sets are shared: callers must not modify them."""
        if criteria.or_tags:
            base: AbstractSet[int] = set()
            for cond in criteria.or_tags:
                base = base | self.hits(cond)
        else:
            base = self.all
        for cond in criteria.and_conds:
            if not base:
                return _EMPTY
            base = base & self.hits(cond)
        for cond in criteria.not_conds:
            if not base:
                break
            base = base - self.hits(cond)
        return base


def _explicit_positions(arn: str, group: _Group) -> list[int]:
    """Rows an explicit selection ARN names, split the way PowerShell splits it.

    Wildcards differ by type: EC2, RDS and EFS match a ``*`` id; FSx, S3, S3 Tables and DynamoDB
    match when the ARN's last colon segment is exactly ``*``. Quirks kept on purpose: ``rds``
    reads segment 6 whatever segment 5 says, an S3 or S3 Tables ARN names a bucket only through
    ``split("/")[1]`` (``arn:aws:s3:::bkt`` and ``bkt/*`` name nothing), DynamoDB rows are never
    matched by name, and a DynamoDB ARN with no ``/`` and no ``*`` matches **every** DynamoDB row
    (PowerShell compares a ``$null`` name with a property the rows do not have).
    """
    parts = arn.split(":")
    resource_type = _part(parts, 2)
    if resource_type is None:
        return []
    kind = resource_type.lower()
    slashed = arn.split("/")
    last_is_wildcard = parts[-1] == "*"
    if kind == "ec2":
        segment = _part(parts, 5)
        if segment is None:
            return []
        sub = segment.split("/")
        what = sub[0].lower()
        if what == "instance":
            return group.with_id("ec2_instance", _part(sub, 1), wildcard=True)
        if what == "volume":
            return group.with_id("ebs_attached", _part(sub, 1), wildcard=True)
        return []
    if kind == "rds":
        return group.with_id("rds", _part(parts, 6), wildcard=True)
    if kind == "elasticfilesystem":
        return group.with_id("efs", _part(slashed, 1), wildcard=True)
    if kind == "fsx":
        if last_is_wildcard:
            return group.of_kind("fsx_volume")
        file_system, volume = _part(slashed, 1), _part(slashed, 2)
        if file_system is None or volume is None:
            return []
        return group.by_id.get(("fsx_volume", (file_system.lower(), volume.lower())), [])
    if kind in ("s3", "s3tables"):
        row_kind = "s3" if kind == "s3" else "s3_table"
        if last_is_wildcard:
            return group.of_kind(row_kind)
        return group.with_id(row_kind, _part(slashed, 1), wildcard=False)
    if kind == "dynamodb":
        if last_is_wildcard or _part(slashed, 1) is None:
            return group.of_kind("dynamodb")
        return []
    return []


# ── the matcher ───────────────────────────────────────────────────────────────────────────────


class _State:
    """The plan names of one row, in PowerShell's append order, with a case-insensitive count."""

    __slots__ = ("names", "count", "in_plan")

    def __init__(self) -> None:
        self.names: list[str] = []
        self.count: dict[str, int] = {}
        self.in_plan = False

    def add(self, name: str, dedupe: bool) -> None:
        """Explicit ARNs append without checking (a plan can name a row twice); the tag path does
        not add a name the row already has."""
        low = name.lower()
        if not (dedupe and self.count.get(low)):
            self.names.append(name)
            self.count[low] = self.count.get(low, 0) + 1
        self.in_plan = True

    def remove(self, name: str) -> None:
        """Drop every occurrence of the plan name; no names left means not in a plan."""
        low = name.lower()
        if self.count.get(low):
            self.names = [n for n in self.names if n.lower() != low]
            self.count[low] = 0
        if not self.names:
            self.in_plan = False


def _group_key(account_id, region) -> tuple[str, str]:
    return (str(account_id), str(region).lower())


def compute_membership(
    plans: Sequence[Mapping],
    rows: Sequence[RowView],
    group_order: Optional[Sequence[tuple[str, str]]] = None,
) -> list[Membership]:
    """One ``Membership`` per row, in the order of ``rows``.

    ``group_order`` is the scan order of (account, region) groups, which decides how far a
    ``NotResources`` entry reaches; groups it does not name follow in the order their rows
    appear, then groups that only have plans. Plans are the dicts of ``result["backup_plans"]``;
    a plan without a ``selections`` key has no selections here (callers decide the fallback).
    """
    groups: dict[tuple[str, str], list[int]] = {}
    for account_id, region in group_order or ():
        groups.setdefault(_group_key(account_id, region), [])
    for pos, row in enumerate(rows):
        groups.setdefault(_group_key(row.account_id, row.region), []).append(pos)
    plans_by_group: dict[tuple[str, str], list[Mapping]] = defaultdict(list)
    for plan in plans:
        key = _group_key(plan.get("account_id", ""), plan.get("region", ""))
        plans_by_group[key].append(plan)
        groups.setdefault(key, [])

    # Only rows whose ARN some selection excludes need to be remembered across groups.
    excluded_arns = {
        arn.lower()
        for plan in plans
        for selection in plan.get("selections") or []
        for arn in selection.get("not_resources") or []
        if isinstance(arn, str)
    }
    seen_by_arn: dict[str, list[int]] = defaultdict(list)
    states: dict[int, _State] = {}

    def state(pos: int) -> _State:
        if pos not in states:
            states[pos] = _State()
        return states[pos]

    for key, positions in groups.items():
        group = _Group(positions, rows)
        if excluded_arns:
            for pos in positions:
                arn = rows[pos].resource_arn
                if arn and arn.lower() in excluded_arns:
                    seen_by_arn[arn.lower()].append(pos)
        for plan in plans_by_group.get(key, ()):
            name = str(plan.get("plan_name") or "")
            for selection in plan.get("selections") or []:
                for arn in selection.get("resources") or []:
                    if isinstance(arn, str):
                        for pos in _explicit_positions(arn, group):
                            state(pos).add(name, dedupe=False)
                criteria = criteria_from_selection(selection)
                if criteria.any():
                    for pos in group.matched(criteria):
                        state(pos).add(name, dedupe=True)
                for arn in selection.get("not_resources") or []:
                    if isinstance(arn, str):
                        for pos in seen_by_arn.get(arn.lower(), ()):
                            if pos in states:
                                states[pos].remove(name)

    result = []
    for pos in range(len(rows)):
        found = states.get(pos)
        result.append(
            Membership(list(found.names), found.in_plan) if found else Membership([], False)
        )
    return result
