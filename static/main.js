// main.js

// Função que redireciona para a tela de login ou diretamente para o chat se o usuário estiver logado
function redirectToLogin() {
    const isLoggedIn = localStorage.getItem('loggedInUser');
    if (isLoggedIn) {
        window.location.href = '/chat'; // Redireciona para o chat
    } else {
        window.location.href = '/login_auth'; // Redireciona para o login
    }
}
