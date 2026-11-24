"""
Unit tests for ip-lookup.py
"""
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import functions by executing the script in a namespace
_script_globals = {}
with patch("dotenv.load_dotenv"):
    with open("ip-lookup.py") as f:
        code = f.read()
        # Remove the main loop - everything after "# -----------" before "while True:"
        code = code.split('if __name__ == "__main__":')[0] if 'if __name__ == "__main__":' in code else code.split("while True:")[0]  # Only get functions, not main loop
        exec(code, _script_globals)

# Extract functions we need
isValidIp = _script_globals['isValidIp']
getMapLink = _script_globals['getMapLink']
getIpApi = _script_globals['getIpApi']
checkAbuseIpDb = _script_globals['checkAbuseIpDb']
checkLatency = _script_globals['checkLatency']
output = _script_globals['output']
checkOpenPortsAndVulns = _script_globals['checkOpenPortsAndVulns']
parsePorts = _script_globals['parsePorts']


class TestValidateIP:
    """Test IP validation function"""

    def test_valid_ipv4(self):
        """Test valid IPv4 address"""
        assert isValidIp("8.8.8.8")

    def test_valid_ipv6(self):
        """Test valid IPv6 address"""
        assert isValidIp("2001:4860:4860::8888")

    def test_empty_ip(self):
        """Test empty IP (should be valid - uses public IP)"""
        assert isValidIp("")

    def test_invalid_ip(self):
        """Test invalid IP address"""
        assert not isValidIp("999.999.999.999")
        assert not isValidIp("invalid.ip.address")
        assert not isValidIp("192.168.1")


class TestMapLink:
    """Test Google Maps link generation"""

    def test_valid_coordinates(self):
        """Test valid latitude and longitude"""
        link = getMapLink(40.7128, -74.0060)
        assert "https://www.google.com/maps" in link
        assert "40.7128" in link
        assert "-74.006" in link

    def test_zero_coordinates(self):
        """Test zero coordinates (valid, equator/prime meridian)"""
        link = getMapLink(0, 0)
        assert "https://www.google.com/maps" in link

    def test_null_coordinates(self):
        """Test None coordinates"""
        link = getMapLink(None, 50.0)
        assert link == "Map link unavailable"

        link = getMapLink(50.0, None)
        assert link == "Map link unavailable"

    def test_both_none_coordinates(self):
        """Test both None coordinates"""
        link = getMapLink(None, None)
        assert link == "Map link unavailable"


class TestGetIpApi:
    """Test IP API function"""

    @patch('requests.get')
    def test_get_public_ip(self, mock_get):
        """Test getting public IP"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "query": "1.1.1.1",
            "country": "USA",
            "city": "Los Angeles"
        }
        mock_get.return_value = mock_response

        result = getIpApi()
        assert result["status"] == "success"
        assert result["query"] == "1.1.1.1"

    @patch('requests.get')
    def test_get_specific_ip(self, mock_get):
        """Test getting information for a specific IP"""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "status": "success",
            "query": "8.8.8.8",
            "country": "USA",
            "isp": "Google"
        }
        mock_get.return_value = mock_response

        result = getIpApi("8.8.8.8")
        assert result["query"] == "8.8.8.8"

    @patch('requests.get')
    def test_get_ip_api_error(self, mock_get):
        """Test error handling in getIpApi"""
        mock_get.side_effect = Exception("Connection error")

        result = getIpApi()
        assert result is None


class TestCheckAbuseIpDb:
    """Test AbuseIPDB checking function"""

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch('requests.get')
    def test_check_clean_ip(self, mock_get):
        """Test checking a clean IP"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "1.1.1.1",
                "totalReports": 0,
                "abuseConfidenceScore": 0,
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_response

        result = checkAbuseIpDb("1.1.1.1")
        assert result["totalReports"] == 0
        assert result["abuseConfidenceScore"] == 0

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "test-key"})
    @patch('requests.get')
    def test_check_reported_ip(self, mock_get):
        """Test checking a reported IP"""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "ipAddress": "192.168.1.1",
                "totalReports": 5,
                "abuseConfidenceScore": 85,
                "isWhitelisted": False
            }
        }
        mock_get.return_value = mock_response

        result = checkAbuseIpDb("192.168.1.1")
        assert result["totalReports"] == 5
        assert result["abuseConfidenceScore"] == 85

    @patch.dict(os.environ, {"ABUSEIPDB_API_KEY": ""})
    @patch('requests.get')
    def test_invalid_api_key(self, mock_get):
        """Test handling of invalid API key"""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = checkAbuseIpDb("8.8.8.8")
        assert result is None

class TestOpenPortsAndVulns:
    """Test Shodan InternetDB open ports & CVE scanner and port parser"""

    def test_parse_ports_valid(self):
        assert parsePorts("80, 443, 22") == [80, 443, 22]

    def test_parse_ports_empty_and_invalid(self):
        assert parsePorts("") == []
        assert parsePorts("80, abc, 0, 70000, 53") == [80, 53]

    @patch('requests.get')
    def test_check_open_ports_success(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "ports": [53, 80, 443],
            "vulns": ["CVE-2023-1234"],
            "hostnames": ["dns.google"]
        }
        mock_get.return_value = mock_response

        result = checkOpenPortsAndVulns("8.8.8.8")
        assert result["ports"] == [53, 80, 443]
        assert "CVE-2023-1234" in result["vulns"]

    @patch('requests.get')
    def test_check_open_ports_404(self, mock_get):
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = checkOpenPortsAndVulns("198.51.100.1")
        assert result["ports"] == []
        assert result["vulns"] == []

    def test_check_open_ports_empty_ip(self):
        assert checkOpenPortsAndVulns("") is None


class TestLatency:
    """Test ping latency check"""

    @patch('subprocess.run')
    def test_reachable_linux_format(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="rtt min/avg/max/mdev = 10.1/14.5/20.2/1.1 ms"
        )
        assert checkLatency("8.8.8.8") == "Reachable (Avg Latency: 14.5ms)"

    @patch('subprocess.run')
    def test_reachable_windows_format(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout="Minimum = 12ms, Maximum = 18ms, Average = 15ms"
        )
        assert checkLatency("8.8.8.8") == "Reachable (Avg Latency: 15ms)"

    @patch('subprocess.run')
    def test_unreachable(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        assert "Unreachable" in checkLatency("192.0.2.1")


class TestOutput:
    """Test console output formatting"""

    def test_output_with_ports_and_abuse(self, capsys):
        ip_data = {
            "status": "success",
            "query": "8.8.8.8",
            "country": "United States",
            "regionName": "Virginia",
            "city": "Ashburn",
            "lat": 39.03,
            "lon": -77.5,
            "isp": "Google LLC",
            "as": "AS15169 Google LLC"
        }
        abuse_data = {
            "totalReports": 10,
            "abuseConfidenceScore": 0,
            "lastReportedAt": "2026-11-10T06:26:48+00:00",
            "usageType": "Content Delivery Network",
            "isWhitelisted": True,
            "ipAddress": "8.8.8.8"
        }
        port_data = {"ports": [53, 443], "vulns": [], "hostnames": ["dns.google"]}

        output(ip_data, abuse_data, "Reachable (Avg Latency: 15ms)", port_data, [443, 22])
        captured = capsys.readouterr().out

        assert "SAFE (Reported, but 0% Abuse Confidence)" in captured
        assert "Port 443: OPEN" in captured
        assert "Port 22: CLOSED / NOT INDEXED" in captured

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
