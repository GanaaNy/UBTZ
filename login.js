// Toggle password visibility
document.getElementById('togglePassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('password');
    const eyeIcon = this.querySelector('.eye-icon');
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        eyeIcon.textContent = '🙈';
    } else {
        passwordInput.type = 'password';
        eyeIcon.textContent = '👁️';
    }
});

// Handle form submission
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const form = this;
    const submitButton = form.querySelector('.login-button');
    const buttonText = submitButton.querySelector('.button-text');
    const buttonLoader = submitButton.querySelector('.button-loader');
    const errorMessage = document.getElementById('errorMessage');
    
    // Get form data
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const rememberMe = document.getElementById('rememberMe').checked;
    
    // Hide previous error
    errorMessage.style.display = 'none';
    
    // Disable button and show loading state
    submitButton.disabled = true;
    buttonText.style.display = 'none';
    buttonLoader.style.display = 'inline';
    
    try {
        // Send login request to backend
        const response = await fetch('http://localhost:5000/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                password: password,
                rememberMe: rememberMe
            })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Store token if provided
            if (data.token) {
                if (rememberMe) {
                    localStorage.setItem('authToken', data.token);
                } else {
                    sessionStorage.setItem('authToken', data.token);
                }
            }
            
            // Store user info if provided
            if (data.user) {
                const storage = rememberMe ? localStorage : sessionStorage;
                storage.setItem('user', JSON.stringify(data.user));
            }
            
            // Redirect to dashboard or home page
            window.location.href = data.redirect || '/dashboard.html';
        } else {
            // Show error message
            errorMessage.textContent = data.message || 'Нэвтрэхэд алдаа гарлаа. Хэрэглэгчийн нэр болон нууц үгээ шалгана уу.';
            errorMessage.style.display = 'block';
        }
    } catch (error) {
        console.error('Login error:', error);
        errorMessage.textContent = 'Сервертэй холбогдох боломжгүй байна. Дахин оролдоно уу.';
        errorMessage.style.display = 'block';
    } finally {
        // Re-enable button and hide loading state
        submitButton.disabled = false;
        buttonText.style.display = 'inline';
        buttonLoader.style.display = 'none';
    }
});

// Check if user is already logged in
window.addEventListener('DOMContentLoaded', function() {
    const token = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
    if (token) {
        // User is already logged in, redirect to dashboard
        window.location.href = '/dashboard.html';
    }
});

