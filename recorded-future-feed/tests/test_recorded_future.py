"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

"""Tests for the Recorded Future Threat Intel Feed connector."""

import gzip
import io

import pytest


@pytest.fixture
def ops(load_connector):
    return load_connector('recorded-future-feed')


def _config(**overrides):
    base = {
        'api_token': 'rf-token',
        'base_url': 'https://api.recordedfuture.com/v2/',
        'verify_ssl': False,
        'malicious_threshold': 65,
        'suspicious_threshold': 25,
        'timeout': 30,
    }
    base.update(overrides)
    return base


def test_client_attaches_xrftoken_header(ops):
    client = ops.RecordedFutureClient(_config())
    assert client.headers['X-RFToken'] == 'rf-token'


def test_client_requires_api_token(ops):
    with pytest.raises(Exception) as exc:
        ops.RecordedFutureClient(_config(api_token=''))
    assert 'API Token' in str(exc.value)


def test_threshold_validation(ops):
    with pytest.raises(Exception) as exc:
        ops.RecordedFutureClient(_config(malicious_threshold=10, suspicious_threshold=20))
    assert 'Malicious Threshold' in str(exc.value) or 'Suspicious' in str(exc.value)


@pytest.mark.parametrize('risk,expected', [
    (90, 3), (65, 3),  # malicious
    (40, 2), (25, 2),  # suspicious
    (10, 0),  # low risk → unknown
    (0, 1),  # explicit 0 → good
    ('not-a-number', 0),  # bad input → unknown
])
def test_score_calculation(ops, risk, expected):
    client = ops.RecordedFutureClient(_config())
    assert client.calculate_score(risk) == expected


def test_normalize_indicator_type_validates(ops):
    assert ops._normalize_indicator_type('IP') == 'ip'
    with pytest.raises(Exception):
        ops._normalize_indicator_type('mystery')


def _gzip_csv(rows):
    buf = io.BytesIO()
    text = '\n'.join(rows).encode('utf-8')
    with gzip.GzipFile(fileobj=buf, mode='wb') as gz:
        gz.write(text)
    return buf.getvalue()


def test_fetch_indicators_parses_gzipped_csv(ops, requests_mock):
    csv_rows = [
        'Name,Risk,RiskString,EvidenceDetails',
        '1.2.3.4,80,"3 of 5 Risk Rules Triggered","{\\"EvidenceDetails\\":[{\\"Rule\\":\\"X\\"}]}"',
        '5.6.7.8,30,"1 of 5 Risk Rules Triggered",',
        '9.9.9.9,5,"0 of 5 Risk Rules Triggered",',
    ]
    body = _gzip_csv(csv_rows)
    requests_mock.get('https://api.recordedfuture.com/v2/ip/risklist', content=body, status_code=200,
                      headers={'Content-Encoding': 'gzip'})
    result = ops.fetch_indicators(_config(), {'indicator_type': 'ip'})
    assert result['count'] == 3
    by_value = {i['value']: i for i in result['indicators']}
    assert by_value['1.2.3.4']['score'] == 3
    assert by_value['5.6.7.8']['score'] == 2
    assert by_value['9.9.9.9']['score'] == 0
    assert by_value['1.2.3.4']['type'] == 'ip'
    assert by_value['1.2.3.4']['source'] == 'recordedfuture.masterrisklist'


def test_fetch_indicators_respects_limit(ops, requests_mock):
    rows = ['Name,Risk,RiskString,EvidenceDetails'] + ['1.1.1.{},10,,'.format(i) for i in range(20)]
    requests_mock.get('https://api.recordedfuture.com/v2/ip/risklist',
                      content=_gzip_csv(rows), status_code=200,
                      headers={'Content-Encoding': 'gzip'})
    result = ops.fetch_indicators(_config(), {'indicator_type': 'ip', 'limit': 5})
    assert result['count'] == 5
    assert result['truncated'] is True


def test_fetch_indicators_passes_risk_rule_query(ops, requests_mock):
    requests_mock.get('https://api.recordedfuture.com/v2/domain/risklist',
                      content=_gzip_csv(['Name,Risk,RiskString,EvidenceDetails',
                                         'evil.example.com,80,,']),
                      status_code=200, headers={'Content-Encoding': 'gzip'})
    ops.fetch_indicators(_config(), {'indicator_type': 'domain', 'risk_rule': 'historicalThreatList'})
    # requests-mock's `qs` lowercases values; check the raw URL to preserve case.
    url = requests_mock.last_request.url
    assert 'list=historicalThreatList' in url
    assert 'gzip=true' in url


def test_unauthorized_raises_clean_error(ops, requests_mock):
    requests_mock.get('https://api.recordedfuture.com/v2/ip/riskrules', status_code=401)
    with pytest.raises(Exception) as exc:
        ops._check_health(_config())
    assert 'Unauthorized' in str(exc.value) or 'Health check failed' in str(exc.value)


def test_health_check_success(ops, requests_mock):
    requests_mock.get('https://api.recordedfuture.com/v2/ip/riskrules', json={'data': {'results': []}}, status_code=200)
    assert ops._check_health(_config()) is True


def test_lookup_ip_uses_correct_path(ops, requests_mock):
    requests_mock.get('https://api.recordedfuture.com/v2/ip/8.8.8.8', json={'data': {'risk': {'score': 50}}},
                      status_code=200)
    result = ops.lookup_ip(_config(), {'ip': '8.8.8.8'})
    assert result['data']['risk']['score'] == 50
    assert requests_mock.last_request.qs['fields'] == ['risk,intelcard,timestamps,counts,sightings']


def test_operations_dispatch_has_all_actions(ops):
    expected = {'fetch_indicators', 'get_risk_rules', 'lookup_ip', 'lookup_domain',
                'lookup_url', 'lookup_hash', 'lookup_vulnerability'}
    assert expected.issubset(set(ops.operations.keys()))
