"""
Unit tests for ip-lookup.py
"""
import pytest
import ipaddress
from unittest.mock import patch, MagicMock
import sys
import os

# Add parent directory to path to import ip_lookup functions
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Mock the dotenv before importing
with patch('dotenv.load_dotenv'):
    # Import functions from the main script
    # Note: Since ip-lookup.py is a script with a main loop,
    # we'll test the utility functions
    exec(open('ip-lookup.py').read(), globals())


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
        assert "-74.0060" in link
    
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
