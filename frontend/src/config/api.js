// API Configuration
const getDefaultApiUrl = () => {
	// CRA injects env vars at build time; if they're missing in production,
	// we should use same-origin routing (reverse proxy to Django at /api).
	if (typeof window !== 'undefined' && window.location && window.location.origin) {
		return `${window.location.origin}/api`;
	}
	return '/api';
};

const API_URL = process.env.REACT_APP_API_URL || getDefaultApiUrl();

export default API_URL;
