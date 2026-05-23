/**
 * Simple API Client - No authentication required
 */

class SimpleScanAPI {
    constructor() {
        this.baseURL = window.location.origin;
    }

    /**
     * Make API request
     */
    async request(url, options = {}) {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers,
            }
        });

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.error || error.detail || 'Request failed');
        }

        return response.json();
    }

    /**
     * Login (fake - always succeeds)
     */
    async login(email, password) {
        return this.request(`${this.baseURL}/api/auth/login/`, {
            method: 'POST',
            body: JSON.stringify({ email, password })
        });
    }

    /**
     * Signup (fake - always succeeds)
     */
    async signup(email, password, fullName) {
        return this.request(`${this.baseURL}/api/auth/signup/`, {
            method: 'POST',
            body: JSON.stringify({ 
                email, 
                password,
                full_name: fullName 
            })
        });
    }

    /**
     * Get scan status
     */
    async getScanStatus() {
        return this.request(`${this.baseURL}/api/scans/status/`);
    }

    /**
     * Start new scan
     */
    async startScan(target, scanType = 'web_security', options = {}) {
        return this.request(`${this.baseURL}/api/scans/start/`, {
            method: 'POST',
            body: JSON.stringify({ 
                target, 
                scan_type: scanType,
                ...options 
            })
        });
    }

    /**
     * Get single scan
     */
    async getScan(scanId) {
        return this.request(`${this.baseURL}/api/scans/${scanId}/`);
    }

    /**
     * Create checkout session (fake)
     */
    async createCheckoutSession(planId, successUrl, cancelUrl) {
        return this.request(`${this.baseURL}/api/billing/checkout/`, {
            method: 'POST',
            body: JSON.stringify({ 
                plan_id: planId,
                success_url: successUrl,
                cancel_url: cancelUrl
            })
        });
    }
}

// Create global API instance
window.api = new SimpleScanAPI();
