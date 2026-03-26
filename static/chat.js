const socket = io();
const chatMessages = document.getElementById('chatMessages');
const msgInput = document.getElementById('msgInput');
const btnSend = document.getElementById('btnSend');
const typingIndicator = document.getElementById('typingIndicator');
const btnAttach = document.getElementById('btnAttach');
const fileInput = document.getElementById('fileInput');

let mySid = null;
socket.on('connect', () => { mySid = socket.id; });

socket.on('user_list', (users) => {
    document.getElementById('onlineCount').innerText = Object.keys(users).length;
    let html = '';
    for(let sid in users){
        html += `<div class="user-item"><div class="user-avatar">${users[sid][0].toUpperCase()}</div><div>${users[sid]}</div></div>`;
    }
    document.getElementById('userList').innerHTML = html;
});

socket.on('history', (msgs) => {
    chatMessages.innerHTML = '';
    msgs.forEach(appendMessage);
});

socket.on('message', (msg) => {
    appendMessage(msg);
});

let typingTimer;
msgInput.addEventListener('input', () => {
    socket.emit('typing');
    clearTimeout(typingTimer);
});

socket.on('typing', (user) => {
    typingIndicator.innerText = `${user} is typing...`;
    typingIndicator.style.display = 'block';
    clearTimeout(typingTimer);
    typingTimer = setTimeout(() => { typingIndicator.style.display = 'none'; }, 2000);
});

socket.on('msg_deleted', (id) => {
    const el = document.getElementById(`msg-${id}`);
    if(el) el.remove();
});

function appendMessage(msg) {
    const isSelf = msg.sid === mySid;
    let contentHtml = '';
    if(msg.type === 'image') contentHtml = `<div class="msg-media"><img src="${msg.data}" onclick="window.open(this.src)"></div>`;
    else if(msg.type === 'voice') contentHtml = `<div class="msg-media"><audio controls src="${msg.data}"></audio></div>`;
    else if(msg.type === 'file') contentHtml = `<div>📄 <a href="${msg.data.url}" target="_blank">${msg.data.name}</a></div>`;
    else contentHtml = `<div class="msg-text">${escapeHtml(msg.data)}</div>`;

    const div = document.createElement('div');
    div.id = `msg-${msg.id}`;
    div.className = `msg-bubble ${isSelf ? 'self' : 'other'}`;
    div.innerHTML = `
        ${isSelf ? `<button class="msg-del" onclick="deleteMsg('${msg.id}')">X</button>` : ''}
        ${!isSelf ? `<div class="msg-user">${msg.user}</div>` : ''}
        ${contentHtml}
        <div class="msg-time">${msg.time}</div>
    `;
    chatMessages.appendChild(div);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function deleteMsg(id) { socket.emit('delete_msg', id); }

function sendMsg() {
    const txt = msgInput.value.trim();
    if(txt){
        socket.emit('message', { type: 'text', data: txt });
        msgInput.value = '';
    }
}
btnSend.addEventListener('click', sendMsg);
msgInput.addEventListener('keypress', e => { if(e.key === 'Enter') sendMsg(); });

function escapeHtml(unsafe) {
    return unsafe.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#039;");
}

// Media attachment handling
btnAttach.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if(!file) return;
    const formData = new FormData();
    formData.append('file', file);
    
    const res = await fetch('/chat_media', { method: 'POST', body: formData });
    const data = await res.json();
    
    const type = file.type.startsWith('image/') ? 'image' : 'file';
    socket.emit('message', { type: type, data: (type === 'image' ? data.url : data) });
});
