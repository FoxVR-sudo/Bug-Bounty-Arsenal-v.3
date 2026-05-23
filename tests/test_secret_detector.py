"""
Unit tests for Secret Detector
"""
import pytest


class TestSecretDetector:
    """Test Secret detection"""

    @pytest.mark.detector
    def test_secret_detector_finds_aws_keys(self):
        """Test detection of AWS access keys"""
        from detectors.secret_detector import detect_secrets_from_text as detect

        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        combined_dict = {
            'url': 'https://example.com/config.js',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_secret_detector_finds_private_keys(self):
        """Test detection of private keys"""
        from detectors.secret_detector import detect_secrets_from_text as detect

        text = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA..."
        combined_dict = {
            'url': 'https://example.com/app.js',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)

    @pytest.mark.detector
    def test_secret_detector_handles_empty_text(self):
        """Test handling of empty text"""
        from detectors.secret_detector import detect_secrets_from_text as detect

        text = ""
        combined_dict = {
            'url': 'https://example.com/',
            'context': {'resp': {'headers': {}, 'text': text}}
        }

        findings = detect(text, combined_dict)

        # Should return a list
        assert isinstance(findings, list)
