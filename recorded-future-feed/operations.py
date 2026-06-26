"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import csv
import json as _json
import zlib

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('recorded-future-feed')

DEFAULT_BASE_URL = 'https://api.recordedfuture.com/v2/'

# Indicator-type → RF endpoint segment.
INDICATOR_TYPES = {
    'ip': 'ip',
    'domain': 'domain',
    'url': 'url',
    'hash': 'hash',
    'vulnerability': 'vulnerability',
}

# Default DBot-equivalent thresholds. Override via config.
DEFAULT_MALICIOUS_THRESHOLD = 65
DEFAULT_SUSPICIOUS_THRESHOLD = 25


class RecordedFutureClient(object):
    def __init__(self, config):
        self.api_token = (config.get('api_token') or '').strip()
        if not self.api_token:
            raise ConnectorError("API Token is required.")
        self.base_url = (config.get('base_url') or DEFAULT_BASE_URL).strip()
        if not self.base_url.endswith('/'):
            self.base_url += '/'
        self.verify_ssl = bool(config.get('verify_ssl', True))
        self.timeout = int(config.get('timeout') or 60)
        self.malicious_threshold = int(config.get('malicious_threshold') or DEFAULT_MALICIOUS_THRESHOLD)
        self.suspicious_threshold = int(config.get('suspicious_threshold') or DEFAULT_SUSPICIOUS_THRESHOLD)
        if self.malicious_threshold <= self.suspicious_threshold:
            raise ConnectorError("'Malicious Threshold' must be greater than 'Suspicious Threshold'.")
        self.headers = {
            'X-RFToken': self.api_token,
            'User-Agent': 'FortiSOAR-RecordedFutureFeed/1.0.0',
        }

    def _request(self, method, path, params=None, stream=False):
        url = self.base_url + path.lstrip('/')
        try:
            resp = requests.request(method, url, headers=self.headers, params=params,
                                    verify=self.verify_ssl, timeout=self.timeout, stream=stream)
        except requests.exceptions.SSLError as e:
            raise ConnectorError('SSL certificate validation failed: {}'.format(e))
        except requests.exceptions.ConnectionError as e:
            raise ConnectorError('Connection error: {}'.format(e))
        except requests.exceptions.Timeout as e:
            raise ConnectorError('Request timed out: {}'.format(e))
        except requests.exceptions.RequestException as e:
            raise ConnectorError('Request failed: {}'.format(e))
        except Exception as e:
            raise ConnectorError('Unexpected error while calling Recorded Future API: {}'.format(e))
        if resp.status_code == 401:
            raise ConnectorError('Unauthorized: invalid Recorded Future API token.')
        if resp.status_code == 403:
            raise ConnectorError('Forbidden: token does not have access to this resource.')
        if resp.status_code == 404:
            raise ConnectorError('Not Found: {}'.format(url))
        if not resp.ok:
            body = resp.text[:500] if not stream else ''
            raise ConnectorError('Recorded Future API error {}: {}'.format(resp.status_code, body))
        return resp

    def calculate_score(self, risk):
        """0=unknown, 1=good, 2=suspicious, 3=malicious — same convention as XSOAR DBot."""
        try:
            r = int(risk)
        except (TypeError, ValueError):
            return 0
        if r >= self.malicious_threshold:
            return 3
        if r >= self.suspicious_threshold:
            return 2
        if r > 0:
            return 0
        return 1


def _client(config):
    return RecordedFutureClient(config)


def _normalize_indicator_type(value):
    v = (value or '').strip().lower()
    if v not in INDICATOR_TYPES:
        raise ConnectorError(
            "Invalid indicator_type '{}'. Must be one of: {}".format(value, ', '.join(INDICATOR_TYPES)))
    return INDICATOR_TYPES[v]


def _stream_risklist_csv(client, indicator_type, risk_rule=None):
    """Streams a risklist CSV (gzip-encoded) from RF and yields parsed dict rows."""
    path = '{}/risklist'.format(indicator_type)
    params = {'gzip': 'true'}
    if risk_rule:
        params['list'] = risk_rule
    resp = client._request('GET', path, params=params, stream=True)
    raw = resp.raw
    decompressor = zlib.decompressobj(zlib.MAX_WBITS + 16)
    buf = ''
    for chunk in resp.iter_content(chunk_size=64 * 1024):
        if not chunk:
            continue
        try:
            buf += decompressor.decompress(chunk).decode('utf-8', errors='replace')
        except zlib.error:
            # Some risklist responses arrive uncompressed despite gzip=true.
            buf += chunk.decode('utf-8', errors='replace')
        # Yield only complete lines; carry the trailing partial line forward.
        if '\n' in buf:
            lines, buf = buf.rsplit('\n', 1)
            yield lines
    if buf:
        yield buf


def fetch_indicators(config, params, **kwargs):
    """Fetches indicators of the given type from RF risklists. Used by data ingestion."""
    client = _client(config)
    indicator_type = _normalize_indicator_type(params.get('indicator_type'))
    risk_rule = (params.get('risk_rule') or '').strip() or None
    limit = params.get('limit')
    try:
        limit = int(limit) if limit is not None and limit != '' else None
    except (TypeError, ValueError):
        limit = None

    leftover = ''
    columns = None
    indicators = []
    count = 0
    for chunk_text in _stream_risklist_csv(client, indicator_type, risk_rule):
        text = leftover + chunk_text
        lines = text.split('\n')
        leftover = ''
        for line in lines:
            if not line:
                continue
            if columns is None:
                columns = next(csv.reader([line]))
                continue
            try:
                row_values = next(csv.reader([line]))
            except StopIteration:
                continue
            if len(row_values) != len(columns):
                # Possibly a partially streamed row — defer.
                leftover = line
                continue
            row = dict(zip(columns, row_values))
            risk = row.get('Risk')
            indicator_value = row.get('Name')
            if not indicator_value:
                continue
            evidence_details = row.get('EvidenceDetails') or ''
            try:
                evidence_details = _json.loads(evidence_details).get('EvidenceDetails', []) if evidence_details else []
            except (ValueError, AttributeError):
                evidence_details = []
            score = client.calculate_score(risk)
            indicators.append({
                'value': indicator_value,
                'type': indicator_type,
                'risk': risk,
                'risk_string': row.get('RiskString'),
                'score': score,
                'evidence_details': evidence_details,
                'source': 'recordedfuture.masterrisklist',
                'risk_rule': risk_rule,
                'raw': row,
            })
            count += 1
            if limit and count >= limit:
                return {'indicators': indicators, 'count': count, 'truncated': True}
    return {'indicators': indicators, 'count': count, 'truncated': False}


def get_risk_rules(config, params, **kwargs):
    client = _client(config)
    indicator_type = _normalize_indicator_type(params.get('indicator_type'))
    resp = client._request('GET', '{}/riskrules'.format(indicator_type))
    return resp.json()


def _lookup(config, params, indicator_type, value_key):
    client = _client(config)
    value = params.get(value_key)
    if not value:
        raise ConnectorError("'{}' is required.".format(value_key))
    fields = params.get('fields') or 'risk,intelCard,timestamps,counts,sightings'
    resp = client._request('GET', '{}/{}'.format(indicator_type, requests.utils.quote(str(value), safe='')),
                           params={'fields': fields})
    return resp.json()


def lookup_ip(config, params, **kwargs):
    return _lookup(config, params, 'ip', 'ip')


def lookup_domain(config, params, **kwargs):
    return _lookup(config, params, 'domain', 'domain')


def lookup_url(config, params, **kwargs):
    return _lookup(config, params, 'url', 'url')


def lookup_hash(config, params, **kwargs):
    return _lookup(config, params, 'hash', 'hash')


def lookup_vulnerability(config, params, **kwargs):
    return _lookup(config, params, 'vulnerability', 'cve')


def _check_health(config, **kwargs):
    """Health: hit /ip/riskrules with a tiny request."""
    try:
        client = _client(config)
        client._request('GET', 'ip/riskrules')
        return True
    except Exception as e:
        logger.exception('Health check failed: {}'.format(e))
        raise ConnectorError('Health check failed: {}'.format(e))


operations = {
    'fetch_indicators': fetch_indicators,
    'get_risk_rules': get_risk_rules,
    'lookup_ip': lookup_ip,
    'lookup_domain': lookup_domain,
    'lookup_url': lookup_url,
    'lookup_hash': lookup_hash,
    'lookup_vulnerability': lookup_vulnerability,
}
