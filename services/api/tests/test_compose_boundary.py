"""Architecture regression: only the control API may have host ingress."""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[3]


def test_control_api_has_loopback_ingress_without_exposing_scanner():
    config = yaml.safe_load((ROOT / 'compose.yaml').read_text())
    services = config['services']
    api = services['api']
    assert api['ports'] == ['127.0.0.1:8000:8000']
    # A service attached exclusively to internal networks has no normal
    # external/host publication path on the runner's Docker engine.
    assert any(not config['networks'][name].get('internal', False)
               for name in api['networks']), 'API needs a separate ingress network'
    assert set(services['scanner']['networks']) == {'control', 'labnet'}
    assert all(config['networks'][n].get('internal') is True
               for n in services['scanner']['networks'])
    for name in ['db', 'redis', 'worker', 'scanner', 'lab', 'dns-lab']:
        assert not services[name].get('ports'), name


def test_dns_fixture_has_no_data_network_credentials_or_host_port():
    config=yaml.safe_load((ROOT/'compose.yaml').read_text())
    fixture=config['services']['dns-lab']
    assert fixture['networks']==['labnet'] and not fixture.get('ports')
    assert not fixture.get('environment') and fixture['read_only'] is True
    assert fixture['cap_drop']==['ALL']
