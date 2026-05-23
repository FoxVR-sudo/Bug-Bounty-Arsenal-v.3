// Global theme management
(function() {
    const THEME_KEY = 'bugbounty-theme';
    
    function getTheme() {
        return localStorage.getItem(THEME_KEY) || 'light';
    }
    
    function setTheme(theme) {
        localStorage.setItem(THEME_KEY, theme);
        applyTheme(theme);
    }
    
    function applyTheme(theme) {
        if (theme === 'dark') {
            document.documentElement.classList.add('dark');
            document.body.classList.add('dark');
        } else {
            document.documentElement.classList.remove('dark');
            document.body.classList.remove('dark');
        }
        
        // Update all theme toggle buttons
        document.querySelectorAll('.theme-toggle-btn').forEach(btn => {
            btn.textContent = theme === 'dark' ? '☀️' : '🌙';
        });
    }
    
    function toggleTheme() {
        const current = getTheme();
        const newTheme = current === 'dark' ? 'light' : 'dark';
        setTheme(newTheme);
    }
    
    // Apply saved theme immediately (before page render)
    applyTheme(getTheme());
    
    // Expose functions globally
    window.themeManager = {
        get: getTheme,
        set: setTheme,
        toggle: toggleTheme,
        apply: applyTheme
    };
    
    // Auto-apply on page load
    document.addEventListener('DOMContentLoaded', function() {
        applyTheme(getTheme());
    });
})();
