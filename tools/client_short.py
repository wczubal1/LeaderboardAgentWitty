"""Query FINRA consolidated short interest data via the Query API."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from client import FinraQueryClient, FinraQueryError, _parse_query_params

DATASET_GROUP = "otcmarket"
DATASET_NAME = "consolidatedShortInterest"
RESERVED_QUERY_KEYS = {"fields", "limit", "offset", "sortFields"}


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch consolidated short interest data from the FINRA Query API.",
    )
    parser.add_argument(
        "--finra-client-id",
        help="FINRA API client id (or set FINRA_CLIENT_ID env).",
    )
    parser.add_argument(
        "--finra-client-secret",
        help="FINRA API client secret (or set FINRA_CLIENT_SECRET env).",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="HTTP timeout for FINRA requests.",
    )
    parser.add_argument(
        "--fields",
        help="Comma separated list of fields to return.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        help="Max number of rows to return.",
    )
    parser.add_argument(
        "--offset",
        type=int,
        help="Offset for pagination.",
    )
    parser.add_argument(
        "--sort-fields",
        help="Comma separated list of fields to sort by.",
    )
    parser.add_argument(
        "--query-params",
        help="URL-style query parameters for filters (e.g. symbolCode=TSLA&limit=5).",
    )
    parser.add_argument(
        "--symbol",
        help="Filter by symbolCode.",
    )
    parser.add_argument(
        "--issue-name",
        help="Filter by issueName (company name).",
    )
    parser.add_argument(
        "--settlement-date",
        help="Filter by settlementDate (YYYY-MM-DD).",
    )
    return parser


def _compare_filter(field_name: str, value: str) -> Dict[str, Any]:
    return {
        "fieldName": field_name,
        "compareType": "EQUAL",
        "fieldValue": value,
    }


def _build_filters(
    args: argparse.Namespace,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    compare_filters: List[Dict[str, Any]] = []
    date_range_filters: List[Dict[str, Any]] = []
    extra_params: Dict[str, Any] = {}

    if args.query_params:
        params = _parse_query_params(args.query_params)
        for key, value in params.items():
            if key in RESERVED_QUERY_KEYS:
                extra_params[key] = value
                continue
            if key == "settlementDate":
                date_range_filters.append(
                    {"fieldName": key, "startDate": value, "endDate": value}
                )
                continue
            if isinstance(value, list):
                for item in value:
                    compare_filters.append(_compare_filter(key, item))
            else:
                compare_filters.append(_compare_filter(key, value))

    if args.symbol:
        compare_filters.append(_compare_filter("symbolCode", args.symbol))
    if args.issue_name:
        compare_filters.append(_compare_filter("issueName", args.issue_name))
    if args.settlement_date:
        date_range_filters.append(
            {
                "fieldName": "settlementDate",
                "startDate": args.settlement_date,
                "endDate": args.settlement_date,
            }
        )

    return compare_filters, date_range_filters, extra_params


def _parse_extra_fields(value: Any) -> Optional[List[str]]:
    if not value:
        return None
    raw = value if isinstance(value, str) else str(value)
    return [part.strip() for part in raw.split(",") if part.strip()]


def _parse_extra_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    client_id = args.finra_client_id or os.environ.get("FINRA_CLIENT_ID")
    client_secret = args.finra_client_secret or os.environ.get("FINRA_CLIENT_SECRET")
    if not client_id or not client_secret:
        parser.error("FINRA client id/secret are required")

    compare_filters, date_range_filters, extra_params = _build_filters(args)

    field_list = (
        [part.strip() for part in args.fields.split(",") if part.strip()]
        if args.fields
        else _parse_extra_fields(extra_params.get("fields"))
    )
    sort_fields = (
        [part.strip() for part in args.sort_fields.split(",") if part.strip()]
        if args.sort_fields
        else _parse_extra_fields(extra_params.get("sortFields"))
    )
    limit = args.limit if args.limit is not None else _parse_extra_int(extra_params.get("limit"))
    offset = (
        args.offset if args.offset is not None else _parse_extra_int(extra_params.get("offset"))
    )

    try:
        with FinraQueryClient(
            client_id=client_id,
            client_secret=client_secret,
            dataset_group=DATASET_GROUP,
            dataset_name=DATASET_NAME,
            timeout=args.timeout,
        ) as query_client:
            payload = query_client.query_dataset_post(
                compare_filters=compare_filters or None,
                date_range_filters=date_range_filters or None,
                fields=field_list,
                limit=limit,
                offset=offset,
                sort_fields=sort_fields,
            )
    except (FinraQueryError, ValueError) as exc:
        sys.stderr.write(f"Error: {exc}\n")
        return 1

    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
