const socket = io.connect('http://localhost:5000');

// Simulando um banco de dados de usuários
const database = {
    users: [
        { username: "pauloarrupiado" },
        { username: "machado98" },
        { username: "picapau" },
        { username: "papaleguas" },
        { username: "piraraponha" },
        { username: "paulatejano" },
        { username: "madalena69" }
    ]
};

// Elementos do DOM
const chatBody = document.getElementById('chatBody');
const messageInput = document.getElementById('messageInput');
const sendButton = document.getElementById('sendButton');
const chatHeader = document.getElementById('chatHeader');
const searchInput = document.getElementById('searchInput');
const searchResults = document.getElementById('searchResults');
const contactsList = document.getElementById('contactsList');

// Estado de contatos adicionados
const userContacts = new Set(['Gabriel']); // Definimos "Gabriel" como contato inicial

// Função para adicionar uma nova mensagem ao chat
function addMessage(content, isSentByUser = true) {
    const messageElement = document.createElement('div');
    messageElement.classList.add('message', isSentByUser ? 'sent' : 'received');
    messageElement.innerHTML = `
        <p>${content}</p>
        <span>${new Date().toLocaleTimeString()}</span>
    `;
    chatBody.appendChild(messageElement);
    chatBody.scrollTop = chatBody.scrollHeight; // Rolagem automática para a última mensagem
}

// Evento de clique para enviar mensagem
sendButton.addEventListener('click', () => {
    const message = messageInput.value.trim();
    if (message) {
        addMessage(message);
        messageInput.value = ''; // Limpa o campo de entrada
    }
});

// Enviar mensagem ao pressionar Enter
messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendButton.click();
});


// Função para atualizar a lista de resultados da pesquisa
searchInput.addEventListener('input', () => {
    const query = searchInput.value.toLowerCase();
    searchResults.innerHTML = ''; // Limpa os resultados anteriores

    if (query) {
        const filteredUsers = database.users.filter(user =>
            user.username.toLowerCase().includes(query) && !userContacts.has(user.username)
        );

        filteredUsers.forEach(user => {
            const li = document.createElement('li');
            li.textContent = user.username;
            li.addEventListener('click', () => addContact(user.username));
            searchResults.appendChild(li);
        });
    }
});

function addContact(username) {
    if (!userContacts.has(username)) {
        userContacts.add(username);

        const li = document.createElement('li');
        li.classList.add('contact');
        li.setAttribute('data-username', username);

        const button = document.createElement('button');
        button.classList.add('contact');
        button.textContent = username;

        // Evento para abrir o chat com o novo contato
        button.addEventListener('click', () => {
            if (chatHeader.textContent !== `Conversa com ${username}`) {
                chatHeader.textContent = `Conversa com ${username}`;
                chatBody.innerHTML = ''; // Limpa a conversa atual
            }
        });

        li.appendChild(button);
        contactsList.appendChild(li);

        // Limpa o campo de pesquisa
        searchInput.value = '';
        searchResults.innerHTML = '';
    }
}



// Função para abrir a conversa com um contato específico
function openChatWithContact(username) {
    if (chatHeader.textContent !== `Conversa com ${username}`) {
        chatHeader.textContent = `Conversa com ${username}`;
        chatBody.innerHTML = ''; // Limpa a conversa atual
        activeContact = username; // Define o contato ativo
    }
}

// Inicializa o evento para os contatos já existentes
document.querySelectorAll('.contact button').forEach(button => {
    button.addEventListener('click', () => {
        const username = button.textContent;
        openChatWithContact(username);
    });
});

// Evento de clique para o botão de logout
document.getElementById('logoutButton').addEventListener('click', () => {
    localStorage.removeItem('loggedInUser'); // Remove o status de login do localStorage
    window.location.href = '/login_auth'; // Redireciona para a tela de login
});