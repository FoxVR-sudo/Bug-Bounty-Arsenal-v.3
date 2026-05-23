/**
 * BugBounty Arsenal API Client
 * Handles all API communications with JWT authentication
 */

class BugBountyAPI {
    constructor() {
        this.baseURL = window.location.origin;
        this.accessToken = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
    }

    /**
     * Get authentication headers
     */
    getHeaders(includeAuth = true) {
        const headers = {
            'Content-Type': 'application/json',
        };

        if (includeAuth && this.accessToken) {
            headers['Authorization'] = `Bearer ${this.accessToken}`;
        }

        return headers;
    }

    /**
     * Get CSRF token from cookie
     */
    getCsrfToken() {
        const name = 'csrftoken';
        let cookieValue = null;
        if (document.cookie && document.cookie !== '') {
            const cookies = document.cookie.split(';');
            for (let i = 0; i < cookies.length; i++) {
                const cookie = cookies[i].trim();
                if (cookie.substring(0, name.length + 1) === (name + '=')) {
                    cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                    break;
                }
            }
        }
        return cookieValue;
    }

    /**
     * Refresh access token using refresh token
     */
    async refreshAccessToken() {
        if (!this.refreshToken) {
            throw new Error('No refresh token available');
        }

        const response = await fetch(`${this.baseURL}/api/auth/refresh/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ refresh: this.refreshToken })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access;
            localStorage.setItem('access_token', data.access);
            return true;
        } else {
            // Refresh token invalid, logout user
            this.logout();
            return false;
        }
    }

    /**
     * Make authenticated API request with automatic token refresh
     */
    async request(url, options = {}) {
        // Include CSRF token for session authentication
        const csrfToken = this.getCsrfToken();
        const headers = {
            ...this.getHeaders(options.auth !== false),
            ...options.headers,
        };
        
        // Add CSRF token for non-GET requests
        if (options.method && options.method !== 'GET' && csrfToken) {
            headers['X-CSRFToken'] = csrfToken;
        }
        
        let response = await fetch(url, {
            ...options,
            credentials: 'same-origin', // Include cookies for session auth
            headers: headers
        });

        // If unauthorized, try to refresh token and retry
        if (response.status === 401 && this.refreshToken && options.auth !== false) {
            const refreshed = await this.refreshAccessToken();
            if (refreshed) {
                // Update headers with new token
                const retryHeaders = {
                    ...this.getHeaders(true),
                    ...options.headers,
                };
                if (options.method && options.method !== 'GET' && csrfToken) {
                    retryHeaders['X-CSRFToken'] = csrfToken;
                }
                
                // Retry request with new token
                response = await fetch(url, {
                    ...options,
                    credentials: 'same-origin',
                    headers: retryHeaders
                });
            }
        }

        return response;
    }

    /**
     * Login user
     */
    async login(email, password) {
        const response = await fetch(`${this.baseURL}/api/auth/login/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ email, password })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access;
            this.refreshToken = data.refresh;
            localStorage.setItem('access_token', data.access);
            localStorage.setItem('refresh_token', data.refresh);
            localStorage.setItem('user_email', email);
            return data;
        } else {
            const error = await response.json();
            throw new Error(error.detail || error.error || 'Login failed');
        }
    }

    /**
     * Signup new user
     */
    async signup(username, email, password, passwordConfirm) {
        const response = await fetch(`${this.baseURL}/api/auth/signup/`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ 
                username,
                email, 
                password,
                password_confirm: passwordConfirm
            })
        });

        if (response.ok) {
            const data = await response.json();
            this.accessToken = data.access;
            this.refreshToken = data.refresh;
            localStorage.setItem('access_token', data.access);
            localStorage.setItem('refresh_token', data.refresh);
            localStorage.setItem('user_email', email);
            return data;
        } else {
            const error = await response.json();
            throw new Error(error.detail || error.errors || error.error || 'Signup failed');
        }
    }

    /**
     * Logout user
     */
    logout() {
        this.accessToken = null;
        this.refreshToken = null;
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        localStorage.removeItem('user_email');
        window.location.href = '/login/';
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return !!this.accessToken;
    }

    // ===== SCAN ENDPOINTS =====

    async getScanStatus() {
        const response = await this.request(`${this.baseURL}/api/scans/status/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch scan status');
    }

    async getScanDetails(scanId) {
        const response = await this.request(`${this.baseURL}/api/scans/${scanId}/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch scan details');
    }

    async startScan(target, scanType = 'web_security', options = {}) {
        const response = await this.request(`${this.baseURL}/api/scans/start/`, {
            method: 'POST',
            body: JSON.stringify({ 
                target, 
                scan_type: scanType,
                ...options 
            })
        });

        if (response.ok) {
            return await response.json();
        }
        const error = await response.json();
        throw new Error(error.detail || error.error || 'Failed to start scan');
    }

    async stopScan(scanId) {
        const response = await this.request(`${this.baseURL}/api/scans/stop/${scanId}/`, {
            method: 'POST'
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to stop scan');
    }

    async validateScope(target) {
        const response = await this.request(`${this.baseURL}/api/scans/validate-scope/`, {
            method: 'POST',
            body: JSON.stringify({ target })
        });

        if (response.ok) {
            return await response.json();
        }
        const error = await response.json();
        throw new Error(error.detail || error.error || 'Invalid scope');
    }

    // ===== BILLING ENDPOINTS =====

    async createCheckoutSession(planId, successUrl, cancelUrl) {
        const response = await this.request(`${this.baseURL}/api/billing/checkout/`, {
            method: 'POST',
            body: JSON.stringify({ 
                plan_id: planId,
                success_url: successUrl,
                cancel_url: cancelUrl
            })
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to create checkout session');
    }

    async getBillingPortal() {
        const response = await this.request(`${this.baseURL}/api/billing/portal/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to get billing portal');
    }

    async buyExtraScans(quantity) {
        const response = await this.request(`${this.baseURL}/api/billing/buy-scans/`, {
            method: 'POST',
            body: JSON.stringify({ quantity })
        });

        if (response.ok) {
            return await response.json();
        }
        const error = await response.json();
        throw new Error(error.detail || error.error || 'Failed to buy extra scans');
    }

    async changeTier(newPlanId) {
        const response = await this.request(`${this.baseURL}/api/subscriptions/change-tier/`, {
            method: 'POST',
            body: JSON.stringify({ new_plan_id: newPlanId })
        });

        if (response.ok) {
            return await response.json();
        }
        const error = await response.json();
        throw new Error(error.detail || error.error || 'Failed to change tier');
    }

    // ===== ADMIN ENDPOINTS =====

    async getAdminStats() {
        const response = await this.request(`${this.baseURL}/api/admin/stats/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch admin stats');
    }

    async getAdminUsers(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = `${this.baseURL}/api/admin/users/${queryString ? '?' + queryString : ''}`;
        const response = await this.request(url);
        
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch users');
    }

    async activateUser(userId) {
        const response = await this.request(`${this.baseURL}/api/admin/users/${userId}/activate/`, {
            method: 'POST'
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to activate user');
    }

    async deactivateUser(userId) {
        const response = await this.request(`${this.baseURL}/api/admin/users/${userId}/deactivate/`, {
            method: 'POST'
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to deactivate user');
    }

    async getAdminScans(params = {}) {
        const queryString = new URLSearchParams(params).toString();
        const url = `${this.baseURL}/api/admin/scans/${queryString ? '?' + queryString : ''}`;
        const response = await this.request(url);
        
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch scans');
    }

    async backupDatabase() {
        const response = await this.request(`${this.baseURL}/api/admin/database/backup/`, {
            method: 'POST'
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to backup database');
    }

    async restoreDatabase(backupFile) {
        const response = await this.request(`${this.baseURL}/api/admin/database/restore/`, {
            method: 'POST',
            body: JSON.stringify({ backup_file: backupFile })
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to restore database');
    }

    async getSystemHealth() {
        const response = await this.request(`${this.baseURL}/api/admin/system-health/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch system health');
    }

    async getCeleryStatus() {
        const response = await this.request(`${this.baseURL}/api/admin/celery-status/`);
        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to fetch Celery status');
    }

    async clearCache() {
        const response = await this.request(`${this.baseURL}/api/admin/clear-cache/`, {
            method: 'POST'
        });

        if (response.ok) {
            return await response.json();
        }
        throw new Error('Failed to clear cache');
    }
}

// Create global API instance
window.api = new BugBountyAPI();

// Check authentication on protected pages
window.addEventListener('DOMContentLoaded', function() {
    const protectedPages = ['/dashboard/', '/admin-panel/'];
    const currentPath = window.location.pathname;
    
    if (protectedPages.some(page => currentPath.startsWith(page))) {
        if (!window.api.isAuthenticated()) {
            window.location.href = '/login/';
        }
    }
});
