/**
 * Landing Page Handler - Pricing and Authentication
 */

// Initialize API client (uses BugBountyAPI from api-client.js)
const api = window.api || new BugBountyAPI();

/**
 * Handle plan selection
 */
async function selectPlan(planId, planName) {
    // Check if user is authenticated
    if (!api.isAuthenticated()) {
        // Redirect to signup with plan in URL
        window.location.href = `/signup/?plan=${planId}`;
        return;
    }
    
    try {
        // Show loading
        showNotification('🔄 Creating checkout session...', 'info');
        
        // Create checkout session
        const successUrl = `${window.location.origin}/dashboard/?upgraded=true`;
        const cancelUrl = `${window.location.origin}/#pricing`;
        
        const result = await api.createCheckoutSession(planId, successUrl, cancelUrl);
        
        if (result.checkout_url) {
            // Redirect to Stripe checkout
            window.location.href = result.checkout_url;
        } else {
            throw new Error('No checkout URL received');
        }
        
    } catch (error) {
        console.error('Checkout error:', error);
        showNotification('❌ ' + error.message, 'error');
    }
}

/**
 * Show notification
 */
function showNotification(message, type = 'info') {
    let container = document.getElementById('notification-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notification-container';
        container.style.cssText = 'position: fixed; top: 20px; right: 20px; z-index: 10000; max-width: 400px;';
        document.body.appendChild(container);
    }
    
    const notification = document.createElement('div');
    notification.style.cssText = `
        background: ${type === 'error' ? '#dc3545' : type === 'success' ? '#28a745' : '#007bff'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        margin-bottom: 10px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        animation: slideInRight 0.3s ease-out;
    `;
    notification.textContent = message;
    
    container.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-in';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add animation styles
const style = document.createElement('style');
style.textContent = `
@keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

@keyframes slideOutRight {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
}
`;
document.head.appendChild(style);

// Make selectPlan available globally
window.selectPlan = selectPlan;
