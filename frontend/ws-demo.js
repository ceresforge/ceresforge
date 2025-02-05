let socket;

const statusElement = document.getElementById('status');
const messagesElement = document.getElementById('messages');
const messageInputElement = document.getElementById('messageInput');

function connectWebSocket() {
    if (socket) {
        socket.close();
    }

    socket = new WebSocket('/websocket');

    socket.addEventListener('open', (event) => {
        statusElement.textContent = 'Connected';
        statusElement.className = 'connected';
    });

    socket.addEventListener('message', (event) => {
        addMessage(event.data, 'received');
    });

    socket.addEventListener('close', (event) => {
        statusElement.textContent = 'Disconnected';
        statusElement.className = 'disconnected';
    });

    socket.addEventListener('error', (event) => {
        console.error('WebSocket error:', event);
        statusElement.textContent = 'Connection Error';
        statusElement.className = 'disconnected';
    });
}

function sendMessage(event) {
    event.preventDefault();
    const message = messageInput.value.trim();

    if (message && socket.readyState === WebSocket.OPEN) {
        socket.send(message);
        addMessage(message, 'sent');
        messageInputElement.value = '';
    }
}

function addMessage(text, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = text;
    messagesElement.appendChild(messageDiv);

    messagesElement.scrollTop = messagesElement.scrollHeight;
}

connectWebSocket();
