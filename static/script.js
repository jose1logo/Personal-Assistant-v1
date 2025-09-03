document.addEventListener('DOMContentLoaded', () => {
    const chatBox = document.getElementById('chat-box');
    const userInput = document.getElementById('user-input');
    const sendBtn = document.getElementById('send-btn');
    const newChatBtn = document.querySelector('.new-chat-btn');
    const chatHistory = document.getElementById('chat-history');
    const sidebar = document.querySelector('.sidebar');
    const sidebarToggle = document.querySelector('.sidebar-toggle');

    let currentSessionId = null;

    const addMessage = (message, sender, labels = []) => {
        const messageElement = document.createElement('div');
        messageElement.classList.add('chat-message', `${sender}-message`);

        const messageContent = document.createElement('div');
        messageContent.classList.add('message-content');

        if (sender === 'bot') {
            messageContent.innerHTML = message;
        } else {
            messageContent.textContent = message;
        }

        messageElement.appendChild(messageContent);

        if (labels.length > 0) {
            const labelsElement = document.createElement('div');
            labelsElement.classList.add('labels');
            labels.forEach(label => {
                const labelElement = document.createElement('span');
                labelElement.classList.add('label');
                labelElement.textContent = label;
                labelsElement.appendChild(labelElement);
            });
            messageElement.appendChild(labelsElement);
        }

        chatBox.appendChild(messageElement);
        chatBox.scrollTop = chatBox.scrollHeight;
    };

    const handleUserInput = async () => {
        const message = userInput.value.trim();
        if (message) {
            addMessage(message, 'user');
            userInput.value = '';

            const loadingElement = document.createElement('div');
            loadingElement.classList.add('loading-animation');
            loadingElement.innerHTML = `
                <div class="loader">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="loader-icon"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
                </div>
            `;
            chatBox.appendChild(loadingElement);
            chatBox.scrollTop = chatBox.scrollHeight;

            try {
                const response = await fetch('/chat', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ message: message, session_id: currentSessionId }),
                });

                const data = await response.json();
                loadingElement.remove();
                if (data.response) {
                    addMessage(data.response, 'bot');
                    if (data.session_id && !currentSessionId) {
                        currentSessionId = data.session_id;
                        loadHistory();
                    }
                } else {
                    addMessage('Error: Could not get a response from the bot.', 'bot');
                }
            } catch (error) {
                console.error('Error:', error);
                loadingElement.remove();
                addMessage('Error: Could not connect to the bot.', 'bot');
            }
        }
    };

    const loadHistory = async () => {
        try {
            const response = await fetch('/history');
            const data = await response.json();
            chatHistory.innerHTML = '';
            data.forEach(session => {
                const historyItem = document.createElement('div');
                historyItem.classList.add('history-item');
                historyItem.textContent = session.summary;
                historyItem.dataset.sessionId = session.id;
                if (session.id === currentSessionId) {
                    historyItem.classList.add('active');
                }
                historyItem.addEventListener('click', () => {
                    currentSessionId = session.id;
                    loadSession(session.id);
                    document.querySelectorAll('.history-item').forEach(item => item.classList.remove('active'));
                    historyItem.classList.add('active');
                });
                chatHistory.appendChild(historyItem);
            });
        } catch (error) {
            console.error('Error:', error);
        }
    };

    const loadSession = async (sessionId) => {
        try {
            const response = await fetch(`/history/${sessionId}`);
            const data = await response.json();
            chatBox.innerHTML = '';
            data.forEach(item => {
                addMessage(item.text, item.role, item.labels || []);
            });
        } catch (error) {
            console.error('Error:', error);
        }
    };

    newChatBtn.addEventListener('click', () => {
        currentSessionId = null;
        chatBox.innerHTML = `
            <div class="chat-message bot-message">
                <p>Hello! How can I help you today?</p>
            </div>
        `;
        document.querySelectorAll('.history-item').forEach(item => item.classList.remove('active'));
    });

    sendBtn.addEventListener('click', handleUserInput);
    userInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            handleUserInput();
        }
    });

    sidebarToggle.addEventListener('click', () => {
        const isClosed = sidebar.classList.toggle('closed');
        const icon = sidebarToggle.querySelector('svg');
        if (isClosed) {
            icon.innerHTML = '<polyline points="9 18 15 12 9 6"></polyline>'; // right arrow
        } else {
            icon.innerHTML = '<polyline points="15 18 9 12 15 6"></polyline>'; // left arrow
        }
    });

    loadHistory();
});
