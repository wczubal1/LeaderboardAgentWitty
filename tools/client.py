"""Simple module for interacting with FINRA's public BrokerCheck endpoints and Query API."""

from __future__ import annotations

import argparse
import json
import time
import sys
import re
from html.parser import HTMLParser
import os
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qsl, urljoin

import requests


class BrokerCheckError(RuntimeError):
    """Raised when BrokerCheck returns an unexpected response."""


class FinraQueryError(RuntimeError):
    """Raised when FINRA Query API calls fail."""


class BrokerCheckClient:
    """Client capable of searching BrokerCheck advisors by name or CRD number."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.brokercheck.finra.org",
        web_base_url: str = "https://brokercheck.finra.org",
        timeout: int = 10,
        session: Optional[requests.Session] = None,
        api_key: Optional[str] = None,
        bootstrap_session: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.web_base_url = web_base_url.rstrip("/")
        self.timeout = timeout
        self._session = session or requests.Session()
        self._bootstrap_session = bootstrap_session
        self._api_key = api_key or os.environ.get("BROKERCHECK_API_KEY")
        self._has_bootstrapped = False

    def search_individuals(
        self,
        *,
        first_name: str,
        last_name: str,
        limit: int = 10,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        """
        Search advisors by first and last name.

        Returns the ``docs`` field from the BrokerCheck search API response.
        """

        if not first_name and not last_name:
            raise ValueError("Either first_name or last_name must be provided")

        query = self._build_name_query(first_name.strip(), last_name.strip())
        params = {
            "q": query,
            "wt": "json",
            "start": max(offset, 0),
            "rows": max(limit, 1),
        }
        url = f"{self.base_url}/search/individual"
        payload = self._perform_request("get", url, params=params)
        return self._extract_docs(payload)

    def get_by_crd(self, crd_number: int) -> Dict[str, Any]:
        """Return the BrokerCheck summary for a CRD number."""

        if not crd_number:
            raise ValueError("crd_number must be provided")

        url = f"{self.base_url}/individual/summary/{crd_number}"
        return self._perform_request("get", url)

    def close(self) -> None:
        """Close the internal requests session."""

        self._session.close()

    def __enter__(self) -> "BrokerCheckClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _perform_request(
        self,
        method: str,
        url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        self._ensure_session_bootstrap()
        headers = {
            "User-Agent": "tau2-brokercheck-client/1.0",
            "Accept": "application/json, text/plain, */*",
            "Referer": f"{self.web_base_url}/",
            "Origin": self.web_base_url,
            "x-requested-with": "XMLHttpRequest",
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key

        response = self._session.request(
            method,
            url,
            params=params,
            json=json_body,
            timeout=self.timeout,
            headers=headers,
        )

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise BrokerCheckError(
                f"BrokerCheck request failed with {response.status_code}: {response.text}"
            ) from exc

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise BrokerCheckError("BrokerCheck returned a non-JSON response") from exc

    @staticmethod
    def _extract_docs(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        """BrokerCheck's search API returns data either under response.docs or hits.hits."""

        if "response" in payload and isinstance(payload["response"], dict):
            return payload["response"].get("docs", [])

        if "hits" in payload and isinstance(payload["hits"], dict):
            hits: Iterable[Any] = payload["hits"].get("hits", [])
            docs: List[Dict[str, Any]] = []
            for hit in hits:
                if isinstance(hit, dict):
                    source = hit.get("_source") or hit
                    if isinstance(source, dict):
                        docs.append(source)
            return docs

        if isinstance(payload, list):
            return payload

        return payload.get("docs", [])

    @staticmethod
    def _build_name_query(first_name: str, last_name: str) -> str:
        """Construct a default Solr-style query string from the provided names."""

        parts = [name for name in (first_name, last_name) if name]
        if not parts:
            raise ValueError("At least one name must be provided")
        return " ".join(parts)

    def _ensure_session_bootstrap(self) -> None:
        """Warm the session with cookies from the public site (required for API access)."""

        if not self._bootstrap_session or self._has_bootstrapped:
            return

        response = self._session.get(
            f"{self.web_base_url}/",
            timeout=self.timeout,
            headers={
                "User-Agent": "tau2-brokercheck-client/1.0",
                "Accept": "text/html",
            },
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise BrokerCheckError(
                f"Failed to bootstrap BrokerCheck session: {response.status_code}"
            ) from exc

        if not self._api_key:
            self._api_key = self._discover_api_key(response.text)

        if not self._api_key:
            raise BrokerCheckError(
                "Unable to discover BrokerCheck API key. Pass api_key explicitly."
            )

        self._has_bootstrapped = True

    def _discover_api_key(self, html: str) -> Optional[str]:
        key = self._find_api_key_in_text(html)
        if key:
            return key

        parser = _ScriptSrcParser()
        parser.feed(html)

        for script_src in parser.scripts[:20]:
            script_url = (
                script_src
                if script_src.startswith("http")
                else urljoin(self.web_base_url, script_src)
            )
            try:
                script_response = self._session.get(
                    script_url,
                    timeout=self.timeout,
                    headers={"User-Agent": "tau2-brokercheck-client/1.0"},
                )
                script_response.raise_for_status()
            except requests.RequestException:
                continue

            key = self._find_api_key_in_text(script_response.text)
            if key:
                return key

        return None

    @staticmethod
    def _find_api_key_in_text(text: str) -> Optional[str]:
        match = re.search(r"apiKey['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-+=]{20,})['\"]", text)
        if match:
            return match.group(1)
        return None


class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.scripts: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Any]) -> None:
        if tag != "script":
            return
        attr_dict = dict(attrs)
        src = attr_dict.get("src")
        if src:
            self.scripts.append(src)


def _parse_query_params(param_string: str) -> Dict[str, Any]:
    params: Dict[str, Any] = {}
    for key, value in parse_qsl(param_string, keep_blank_values=True):
        if not key:
            continue
        if key in params:
            existing = params[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                params[key] = [existing, value]
        else:
            params[key] = value
    return params


class FinraQueryClient:
    """Client for FINRA's Query API (OAuth2 client-credentials flow)."""

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        *,
        token_url: str = "https://ews.fip.finra.org/fip/rest/ews/oauth2/access_token",
        data_base_url: str = "https://api.finra.org/data",
        dataset_group: str = "registration",
        dataset_name: str = "compositeindividual",
        timeout: int = 30,
        session: Optional[requests.Session] = None,
    ) -> None:
        if not client_id or not client_secret:
            raise ValueError("FINRA client_id and client_secret are required")
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url
        self.data_base_url = data_base_url.rstrip("/")
        self.dataset_group = dataset_group
        self.dataset_name = dataset_name
        self.timeout = timeout
        self._session = session or requests.Session()
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0.0
        self._last_token_response: Optional[Dict[str, Any]] = None

    def get_individual_by_crd(
        self,
        crd_number: str,
        *,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Fetch composite individual record via GET /id/{crd}."""

        if not crd_number:
            raise ValueError("crd_number must be provided")

        url = (
            f"{self.data_base_url}/group/{self.dataset_group}/"
            f"name/{self.dataset_name}/id/{crd_number}"
        )
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = fields

        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Accept": "application/json",
        }
        response = self._session.get(
            url,
            params=params,
            headers=headers,
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise FinraQueryError(
                f"FINRA Query API failed ({response.status_code}): {response.text}"
            ) from exc

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise FinraQueryError("FINRA Query API returned non-JSON response") from exc

    def test_connection(self) -> Dict[str, Any]:
        """Return metadata about an authenticated session without performing a dataset call."""

        token = self._get_access_token()
        seconds_remaining = max(int(self._token_expiry - time.time()), 0)
        token_preview = token[:8] + "..." if len(token) > 8 else token
        last_response = self._last_token_response or {}
        return {
            "status": "ok",
            "token_preview": token_preview,
            "expires_in_seconds": seconds_remaining,
            "scopes": last_response.get("scope"),
            "token_type": last_response.get("token_type"),
        }

    def query_dataset(
        self,
        *,
        params: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort_fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Call GET /group/{dataset_group}/name/{dataset_name} with optional query parameters."""

        query_params: Dict[str, Any] = {}
        if params:
            query_params.update(params)
        if fields:
            query_params["fields"] = fields
        if limit is not None:
            query_params["limit"] = limit
        if offset is not None:
            query_params["offset"] = offset
        if sort_fields:
            query_params["sortFields"] = sort_fields

        url = (
            f"{self.data_base_url}/group/{self.dataset_group}/"
            f"name/{self.dataset_name}"
        )
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Accept": "application/json",
        }
        response = self._session.get(
            url,
            params=query_params,
            headers=headers,
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise FinraQueryError(
                f"FINRA dataset query failed ({response.status_code}): {response.text}"
            ) from exc

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise FinraQueryError("FINRA dataset query returned non-JSON response") from exc

    def query_dataset_post(
        self,
        *,
        compare_filters: Optional[List[Dict[str, Any]]] = None,
        date_range_filters: Optional[List[Dict[str, Any]]] = None,
        fields: Optional[List[str]] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        sort_fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Call POST /group/{dataset_group}/name/{dataset_name} with JSON filters."""

        body: Dict[str, Any] = {}
        if compare_filters:
            body["compareFilters"] = compare_filters
        if date_range_filters:
            body["dateRangeFilters"] = date_range_filters
        if fields:
            body["fields"] = fields
        if limit is not None:
            body["limit"] = limit
        if offset is not None:
            body["offset"] = offset
        if sort_fields:
            body["sortFields"] = sort_fields

        url = (
            f"{self.data_base_url}/group/{self.dataset_group}/"
            f"name/{self.dataset_name}"
        )
        headers = {
            "Authorization": f"Bearer {self._get_access_token()}",
            "Accept": "application/json",
        }
        response = self._session.post(
            url,
            json=body,
            headers=headers,
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise FinraQueryError(
                f"FINRA dataset query failed ({response.status_code}): {response.text}"
            ) from exc

        try:
            return response.json()
        except ValueError as exc:  # pragma: no cover - defensive
            raise FinraQueryError("FINRA dataset query returned non-JSON response") from exc

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> "FinraQueryClient":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _get_access_token(self) -> str:
        now = time.time()
        if self._access_token and now < self._token_expiry:
            return self._access_token

        response = self._session.post(
            self.token_url,
            data={"grant_type": "client_credentials"},
            auth=(self.client_id, self.client_secret),
            timeout=self.timeout,
        )
        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            raise FinraQueryError(
                f"Failed to obtain FINRA access token ({response.status_code}): {response.text}"
            ) from exc

        payload = response.json()
        token = payload.get("access_token")
        expires_in = payload.get("expires_in", 0)
        if not token:
            raise FinraQueryError("FINRA token response missing access_token")
        # subtract a small buffer
        self._access_token = token
        self._token_expiry = now + max(int(expires_in) - 30, 0)
        self._last_token_response = payload
        return token


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Query FINRA BrokerCheck for advisors using CRD or name filters.",
    )
    parser.add_argument("--crd", type=int, help="CRD number for a specific advisor")
    parser.add_argument("--first", help="Advisor first name")
    parser.add_argument("--last", help="Advisor last name")
    parser.add_argument("--limit", type=int, default=10, help="Max rows for name search")
    parser.add_argument("--offset", type=int, default=0, help="Result offset for pagination")
    parser.add_argument(
        "--timeout", type=int, default=10, help="HTTP timeout for BrokerCheck requests"
    )
    parser.add_argument(
        "--api-key",
        help="Optional BrokerCheck API key (otherwise autodetected from the website).",
    )
    parser.add_argument(
        "--use-query-api",
        action="store_true",
        help="Use FINRA Query API (requires client id/secret) instead of BrokerCheck.",
    )
    parser.add_argument(
        "--test-query-api-auth",
        action="store_true",
        help="Only verify FINRA Query API credentials and print token metadata.",
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
        "--finra-query-dataset",
        action="store_true",
        help="Call FINRA's dataset query endpoint instead of fetching by CRD.",
    )
    parser.add_argument(
        "--finra-dataset",
        default="compositeindividual",
        help="FINRA dataset name to query (default: compositeindividual).",
    )
    parser.add_argument(
        "--finra-dataset-group",
        default="registration",
        help="FINRA dataset group to query (default: registration).",
    )
    parser.add_argument(
        "--fields",
        help="Comma separated list of fields to request from the FINRA dataset.",
    )
    parser.add_argument(
        "--finra-query-params",
        help="URL-style query parameters for dataset queries (e.g. symbol=TSLA&limit=5).",
    )
    parser.add_argument(
        "--finra-limit",
        type=int,
        help="Limit value for FINRA dataset queries.",
    )
    parser.add_argument(
        "--finra-offset",
        type=int,
        help="Offset value for FINRA dataset queries.",
    )
    parser.add_argument(
        "--finra-sort-fields",
        help="Comma separated list of sort fields for FINRA dataset queries.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    if args.test_query_api_auth and not args.use_query_api:
        parser.error("--test-query-api-auth requires --use-query-api")

    if args.use_query_api:
        if not args.test_query_api_auth and not args.finra_query_dataset and not args.crd:
            parser.error(
                "--use-query-api requires --crd unless --test-query-api-auth or --finra-query-dataset is provided"
            )
        client_id = args.finra_client_id or os.environ.get("FINRA_CLIENT_ID")
        client_secret = args.finra_client_secret or os.environ.get("FINRA_CLIENT_SECRET")
        field_list = (
            [part.strip() for part in args.fields.split(",") if part.strip()]
            if args.fields
            else None
        )
        sort_fields = (
            [part.strip() for part in args.finra_sort_fields.split(",") if part.strip()]
            if args.finra_sort_fields
            else None
        )
        query_params = (
            _parse_query_params(args.finra_query_params)
            if args.finra_query_params
            else {}
        )
        try:
            with FinraQueryClient(
                client_id=client_id or "",
                client_secret=client_secret or "",
                dataset_group=args.finra_dataset_group,
                dataset_name=args.finra_dataset,
                timeout=args.timeout,
            ) as query_client:
                if args.test_query_api_auth:
                    payload = query_client.test_connection()
                elif args.finra_query_dataset:
                    payload = query_client.query_dataset(
                        params=query_params or None,
                        fields=field_list,
                        limit=args.finra_limit,
                        offset=args.finra_offset,
                        sort_fields=sort_fields,
                    )
                else:
                    payload = query_client.get_individual_by_crd(str(args.crd), fields=field_list)
        except (FinraQueryError, ValueError) as exc:
            sys.stderr.write(f"Error: {exc}\n")
            return 1
    else:
        if not args.crd and not args.first and not args.last:
            parser.error("Provide either --crd or a combination of --first/--last")

        try:
            with BrokerCheckClient(timeout=args.timeout, api_key=args.api_key) as client:
                if args.crd:
                    payload = client.get_by_crd(args.crd)
                else:
                    payload = client.search_individuals(
                        first_name=args.first or "",
                        last_name=args.last or "",
                        limit=args.limit,
                        offset=args.offset,
                    )
        except BrokerCheckError as exc:
            sys.stderr.write(f"Error: {exc}\n")
            return 1

    json.dump(payload, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
