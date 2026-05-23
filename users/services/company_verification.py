"""
Company verification service using OpenCorporates API
Supports international company lookups
"""
import requests
from django.conf import settings
from django.utils import timezone


class CompanyVerificationService:
    """
    Verify company registration using OpenCorporates API
    Free tier: 500 requests/month
    Paid tier: $99/month for 10,000 requests
    """

    BASE_URL = 'https://api.opencorporates.com/v0.4'

    def __init__(self):
        self.api_key = getattr(settings, 'OPENCORPORATES_API_KEY', None)
        self.use_api = bool(self.api_key)

    def search_company(self, company_name, country_code=None, registration_number=None):
        """
        Search for company by name and/or registration number

        Args:
            company_name: Company name
            country_code: ISO 2-letter country code (e.g., 'bg', 'us', 'gb')
            registration_number: Company registration/VAT number

        Returns:
            {
                'found': bool,
                'data': dict or None,
                'message': str
            }
        """
        if not self.use_api:
            return self._mock_verification(company_name, country_code, registration_number)

        try:
            # Build search URL
            if registration_number:
                # Search by registration number (more accurate)
                url = f"{self.BASE_URL}/companies/search"
                params = {
                    'q': registration_number,
                    'api_token': self.api_key,
                }
                if country_code:
                    params['jurisdiction_code'] = country_code.lower()
            else:
                # Search by name
                url = f"{self.BASE_URL}/companies/search"
                params = {
                    'q': company_name,
                    'api_token': self.api_key,
                }
                if country_code:
                    params['jurisdiction_code'] = country_code.lower()

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                companies = data.get('results', {}).get('companies', [])

                if companies:
                    # Get first match
                    company = companies[0]['company']

                    return {
                        'found': True,
                        'data': {
                            'name': company.get('name'),
                            'registration_number': company.get('company_number'),
                            'jurisdiction': company.get('jurisdiction_code'),
                            'incorporation_date': company.get('incorporation_date'),
                            'company_type': company.get('company_type'),
                            'status': company.get('current_status'),
                            'address': company.get('registered_address_in_full'),
                            'opencorporates_url': company.get('opencorporates_url'),
                        },
                        'message': 'Company found in registry'
                    }
                else:
                    return {
                        'found': False,
                        'data': None,
                        'message': 'Company not found in registry'
                    }

            elif response.status_code == 401:
                return {
                    'found': False,
                    'data': None,
                    'message': 'Invalid API key'
                }

            elif response.status_code == 403:
                return {
                    'found': False,
                    'data': None,
                    'message': 'API rate limit exceeded'
                }

            else:
                return {
                    'found': False,
                    'data': None,
                    'message': f'API error: {response.status_code}'
                }

        except requests.RequestException as e:
            return {
                'found': False,
                'data': None,
                'message': f'Network error: {str(e)}'
            }

    def verify_company(self, user, company_name, registration_number, country_code):
        """
        Verify company and update user record

        Returns: (success: bool, message: str, data: dict)
        """
        # Search for company
        result = self.search_company(company_name, country_code, registration_number)

        if result['found']:
            # Update user company info
            user.company_name = company_name
            user.company_registration_number = registration_number
            user.company_country = country_code.upper()
            user.company_verified = True
            user.company_verification_date = timezone.now()

            # Store additional data in a JSON field if available
            # (you may need to add this field to User model)
            # user.company_verification_data = result['data']

            user.save()

            return True, 'Company verified successfully', result['data']

        else:
            # Company not found - require manual verification
            user.company_name = company_name
            user.company_registration_number = registration_number
            user.company_country = country_code.upper()
            user.company_verified = False
            user.save()

            # TODO: Create pending verification request for admin review
            # PendingCompanyVerification.objects.create(user=user, ...)

            return False, 'Company not found. Manual verification required.', None

    def _mock_verification(self, company_name, country_code, registration_number):
        """
        Mock verification for development/testing without API key
        """
        print("=" * 60)
        print("🏢 COMPANY VERIFICATION (Mock Mode - No API Key)")
        print("=" * 60)
        print(f"Company: {company_name}")
        print(f"Country: {country_code}")
        print(f"Registration #: {registration_number}")
        print("=" * 60)

        # Return mock success for testing
        return {
            'found': True,
            'data': {
                'name': company_name,
                'registration_number': registration_number,
                'jurisdiction': country_code,
                'incorporation_date': '2020-01-01',
                'company_type': 'Limited Company',
                'status': 'Active',
                'address': 'Mock address for testing',
                'opencorporates_url': 'https://opencorporates.com/mock',
            },
            'message': 'Company verified (mock mode)'
        }

    @staticmethod
    def get_supported_countries():
        """
        Get list of supported countries for company verification
        """
        return {
            'bg': 'Bulgaria',
            'us': 'United States',
            'gb': 'United Kingdom',
            'de': 'Germany',
            'fr': 'France',
            'es': 'Spain',
            'it': 'Italy',
            'nl': 'Netherlands',
            'be': 'Belgium',
            'at': 'Austria',
            'ch': 'Switzerland',
            'pl': 'Poland',
            'ro': 'Romania',
            'gr': 'Greece',
            'cz': 'Czech Republic',
            'se': 'Sweden',
            'dk': 'Denmark',
            'no': 'Norway',
            'fi': 'Finland',
            'ie': 'Ireland',
            'pt': 'Portugal',
            'ca': 'Canada',
            'au': 'Australia',
            'nz': 'New Zealand',
            'sg': 'Singapore',
            'hk': 'Hong Kong',
            'jp': 'Japan',
            'kr': 'South Korea',
            'in': 'India',
            'br': 'Brazil',
            'mx': 'Mexico',
            'ar': 'Argentina',
            'cl': 'Chile',
            'za': 'South Africa',
            'ae': 'United Arab Emirates',
            'il': 'Israel',
            'tr': 'Turkey',
            'ru': 'Russia',
            'ua': 'Ukraine',
        }

    @staticmethod
    def validate_registration_number(registration_number, country_code):
        """
        Validate registration number format based on country

        Returns: (valid: bool, message: str)
        """
        # Remove spaces and special characters
        clean_number = registration_number.replace(' ', '').replace('-', '').replace('.', '')

        # Country-specific validation
        validators = {
            'bg': lambda n: len(n) in [9, 13] and n.isdigit(),  # Bulgarian UIC/VAT
            'us': lambda n: len(n) >= 5,  # US EIN or state registration
            'gb': lambda n: len(n) == 8 or (len(n) == 10 and n.startswith('SC')),  # UK Companies House
            'de': lambda n: len(n) in [9, 11] and n.isdigit(),  # German HRB/HRA
            'fr': lambda n: len(n) == 9 and n.isdigit(),  # French SIREN
        }

        validator = validators.get(country_code.lower())

        if validator:
            if validator(clean_number):
                return True, 'Valid registration number format'
            else:
                return False, f'Invalid registration number format for {country_code.upper()}'
        else:
            # No specific validation for this country - accept any non-empty
            if len(clean_number) >= 3:
                return True, 'Registration number accepted (no specific validation for country)'
            else:
                return False, 'Registration number too short'

    def get_company_details(self, jurisdiction_code, company_number):
        """
        Get detailed company information

        Args:
            jurisdiction_code: Country/jurisdiction code (e.g., 'bg', 'us_de')
            company_number: Company registration number

        Returns: dict with company details
        """
        if not self.use_api:
            return self._mock_verification(None, jurisdiction_code, company_number)

        try:
            url = f"{self.BASE_URL}/companies/{jurisdiction_code}/{company_number}"
            params = {'api_token': self.api_key}

            response = requests.get(url, params=params, timeout=10)

            if response.status_code == 200:
                data = response.json()
                company = data.get('results', {}).get('company', {})

                return {
                    'found': True,
                    'data': {
                        'name': company.get('name'),
                        'registration_number': company.get('company_number'),
                        'jurisdiction': company.get('jurisdiction_code'),
                        'incorporation_date': company.get('incorporation_date'),
                        'dissolution_date': company.get('dissolution_date'),
                        'company_type': company.get('company_type'),
                        'status': company.get('current_status'),
                        'address': company.get('registered_address_in_full'),
                        'industry_codes': company.get('industry_codes', []),
                        'previous_names': company.get('previous_names', []),
                        'officers': company.get('officers', []),
                        'opencorporates_url': company.get('opencorporates_url'),
                    },
                    'message': 'Company details retrieved'
                }
            else:
                return {
                    'found': False,
                    'data': None,
                    'message': f'API error: {response.status_code}'
                }

        except requests.RequestException as e:
            return {
                'found': False,
                'data': None,
                'message': f'Network error: {str(e)}'
            }
