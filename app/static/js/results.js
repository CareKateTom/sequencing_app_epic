/**
 * Results page functionality for the Heart Failure Analysis app
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tab functionality
    initTabFunctionality();
    
    // Initialize submit new form button
    initSubmitNewFormButton();
});

/**
 * Initialize tab functionality
 */
function initTabFunctionality() {
    // Get all tab links
    const tabLinks = document.querySelectorAll('.nav-link');
    
    // Add click event to each tab link
    tabLinks.forEach(function(tabLink) {
        tabLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Remove active class from all tabs and tab panes
            document.querySelectorAll('.nav-link').forEach(function(link) {
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
 * Initialize the Submit New Form button
 */
function initSubmitNewFormButton() {
    const submitNewFormBtn = document.getElementById('submitNewFormBtn');
    if (submitNewFormBtn) {
        submitNewFormBtn.addEventListener('click', function(e) {
            e.preventDefault();
            
            // Check if warning should be shown
            if (shouldShowWarning()) {
                // Show the warning modal
                document.getElementById('clearWarningModal').style.display = 'block';
            } else {
                // Skip warning and clear directly
                clearAndSubmitNewForm();
            }
        });
    }
}

/**
 * Check if warning should be shown
 */
function shouldShowWarning() {
    // Get cookie value (using app-specific cookie name)
    const warningPref = getCookie('show_form_clear_warning');
    // If cookie doesn't exist or is set to 'true', show warning
    return warningPref === null || warningPref === 'true';
}

/**
 * Proceed with clearing after warning
 */
function proceedWithClear() {
    // Check if "don't show again" is checked
    const dontShowAgain = document.getElementById('dontShowAgain');
    
    if (dontShowAgain && dontShowAgain.checked) {
        // Set cookie to remember preference
        const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
        
        fetch('/set_warning_preference', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify({ show_warning: 'false' }),
        });
    }
    
    // Close modal and clear form
    closeWarningModal();
    clearAndSubmitNewForm();
}

/**
 * Function to actually clear form and redirect
 */
function clearAndSubmitNewForm() {
    // Create a form to submit
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = '/submit_new_form';
    
    // Add CSRF token to the form
    const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');
    const csrfInput = document.createElement('input');
    csrfInput.type = 'hidden';
    csrfInput.name = 'csrf_token';
    csrfInput.value = csrfToken;
    form.appendChild(csrfInput);
    
    document.body.appendChild(form);
    form.submit();
}

/**
 * Close warning modal
 */
function closeWarningModal() {
    document.getElementById('clearWarningModal').style.display = 'none';
}