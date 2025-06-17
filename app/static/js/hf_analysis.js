/**
 * Heart Failure Analysis page functionality
 * Handles tab switching and UI interactions for HF analysis results
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tab functionality
    initTabFunctionality();
    
    // Initialize any additional HF analysis features
    initHFAnalysisFeatures();
});

/**
 * Initialize tab functionality for analysis results
 */
function initTabFunctionality() {
    // Get all tab links
    const tabLinks = document.querySelectorAll('[role="tab"]');
    
    // Add click event to each tab link
    tabLinks.forEach(function(tabLink) {
        tabLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all tabs and tab panes
            document.querySelectorAll('[role="tab"]').forEach(function(link) {
                link.classList.remove('active');
                link.setAttribute('aria-selected', 'false');
            });
            
            document.querySelectorAll('.tab-pane').forEach(function(pane) {
                pane.classList.remove('show', 'active');
            });
            
            // Add active class to clicked tab and corresponding tab pane
            this.classList.add('active');
            this.setAttribute('aria-selected', 'true');
            
            const targetId = this.getAttribute('href').substring(1);
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add('show', 'active');
            }
        });
    });
}

/**
 * Initialize Heart Failure analysis specific features
 */
function initHFAnalysisFeatures() {
    // Add any HF-specific functionality here
    // For example: tooltips, risk variable explanations, etc.
    
    // Initialize tooltips if needed
    initRiskVariableTooltips();
    
    // Initialize any collapsible sections
    initCollapsibleSections();
}

/**
 * Initialize tooltips for risk variables (future enhancement)
 */
function initRiskVariableTooltips() {
    // Future: Add tooltips to explain risk variables
    // This keeps the interface clean while providing help when needed
}

/**
 * Initialize collapsible sections (future enhancement)
 */
function initCollapsibleSections() {
    // Future: Add collapsible sections for detailed risk variable info
    // Keeps the interface uncluttered by default
}