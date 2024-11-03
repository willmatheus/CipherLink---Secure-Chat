// auth.js
// Seleciona elementos
const loginScreen = document.getElementById('loginScreen');
const registerScreen = document.getElementById('registerScreen');
const showRegister = document.getElementById('showRegister');
const showLogin = document.getElementById('showLogin');

// Alterna para a tela de cadastro
showRegister.addEventListener('click', () => {
    loginScreen.classList.add('hidden');
    registerScreen.classList.remove('hidden');
});

// Alterna para a tela de login
showLogin.addEventListener('click', () => {
    registerScreen.classList.add('hidden');
    loginScreen.classList.remove('hidden');
});

// Manipula o formulário de cadastro
document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;

    const response = await fetch('/register', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        alert('Cadastro realizado com sucesso! Faça login para acessar o chat.');
        registerScreen.classList.add('hidden');
        loginScreen.classList.remove('hidden');
    } else {
        const errorText = await response.text(); // Tente obter a resposta como texto
        try {
            const error = JSON.parse(errorText); // Tente interpretar como JSON
            alert(error.message || 'Erro ao realizar operação.');
        } catch (e) {
            alert('Erro desconhecido.'); // Se não for JSON, apenas mostre uma mensagem genérica
        }
    }
});

// No evento de login, salva o usuário como "loggedInUser"
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('loginUsername').value;
    const password = document.getElementById('loginPassword').value;

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    });

    if (response.ok) {
        const data = await response.json();
        localStorage.setItem('loggedInUser', username); // Define o usuário como logado
        alert(`Bem-vindo, ${data.username}!`);
        window.location.href = '/chat'; // Redireciona para o chat
    } else {
        const error = await response.json();
        alert(error.message || 'Usuário ou senha incorretos!');
    }
});
