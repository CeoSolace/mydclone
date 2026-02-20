import React, { useEffect, useState, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import useSocket from '../hooks/useSocket';
import { Picker } from 'emoji-mart';
import 'emoji-mart/css/emoji-mart.css';

// Channel view.  Handles real‑time messaging via Socket.IO.  Supports
// sending text, emojis and images, and displays moderation/info messages.
const ChannelView = () => {
  const { channelId } = useParams();
  const { token, user } = useAuth();
  const socket = useSocket(token);
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [showEmoji, setShowEmoji] = useState(false);
  const [error, setError] = useState(null);
  const [info, setInfo] = useState(null);
  const bottomRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    if (!socket) return;
    // Join channel
    socket.emit('joinChannel', channelId);
    // Receive encryption key (not used client‑side as encryption happens on server)
    const onKey = ({ channelId: id, key }) => {
      // No action needed client side; encryption handled server‑side
    };
    // Receive history
    const onHistory = ({ channelId: id, messages: msgs }) => {
      setMessages(msgs);
    };
    const onNew = ({ channelId: id, message }) => {
      setMessages((prev) => [...prev, message]);
    };
    const onError = (msg) => {
      setError(msg);
    };
    const onInfo = (msg) => {
      setInfo(msg);
      setTimeout(() => setInfo(null), 5000);
    };
    socket.on('channelKey', onKey);
    socket.on('messageHistory', onHistory);
    socket.on('newMessage', onNew);
    socket.on('errorMessage', onError);
    socket.on('infoMessage', onInfo);
    return () => {
      socket.emit('leaveChannel', channelId);
      socket.off('channelKey', onKey);
      socket.off('messageHistory', onHistory);
      socket.off('newMessage', onNew);
      socket.off('errorMessage', onError);
      socket.off('infoMessage', onInfo);
    };
  }, [socket, channelId]);

  // Scroll to bottom when messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const handleSend = () => {
    if (!input.trim()) return;
    socket.emit('sendMessage', { channelId, content: input });
    setInput('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const handleFile = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch('/api/upload', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Upload failed');
      // Send message containing the image URL
      socket.emit('sendMessage', { channelId, content: data.url });
    } catch (err) {
      setError(err.message);
    }
  };

  const addEmoji = (emoji) => {
    setInput((prev) => prev + emoji.native);
  };

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="p-3 bg-gray-900 flex items-center">
        <button
          onClick={() => navigate(-1)}
          className="mr-3 text-blue-400 hover:underline"
        >
          ← Back
        </button>
        <h2 className="text-lg font-bold">Channel</h2>
      </div>
      {/* Messages area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-gray-800">
        {messages.map((m) => (
          <div key={m.id} className="flex flex-col">
            <span className="text-sm text-gray-400">
              {m.author === user._id ? 'You' : m.author} • {new Date(m.createdAt).toLocaleTimeString()}
            </span>
            {m.content.match(/^https?:\/\//) ? (
              m.content.match(/\.(png|jpg|jpeg|gif|webp)$/i) ? (
                <img src={m.content} alt="attachment" className="max-w-xs rounded" />
              ) : (
                <a href={m.content} target="_blank" rel="noopener noreferrer" className="text-blue-400 underline">
                  {m.content}
                </a>
              )
            ) : (
              <p className="whitespace-pre-wrap">{m.content}</p>
            )}
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      {/* Info/Error messages */}
      {info && (
        <div className="p-2 bg-blue-700 text-white text-center text-sm">{info}</div>
      )}
      {error && (
        <div className="p-2 bg-red-600 text-white text-center text-sm" onClick={() => setError(null)}>
          {error}
        </div>
      )}
      {/* Input area */}
      <div className="p-3 bg-gray-900">
        <div className="flex items-end space-x-2">
          <button
            onClick={() => setShowEmoji((s) => !s)}
            className="text-2xl hover:text-gray-300"
          >
            😊
          </button>
          <input
            type="file"
            accept="image/*"
            onChange={handleFile}
            className="hidden"
            id="fileInput"
          />
          <label htmlFor="fileInput" className="cursor-pointer text-2xl hover:text-gray-300">📷</label>
          <textarea
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={1}
            placeholder="Type a message..."
            className="flex-1 p-2 rounded bg-gray-700 text-white resize-none"
          />
          <button
            onClick={handleSend}
            className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded"
          >
            Send
          </button>
        </div>
        {showEmoji && (
          <div className="absolute bottom-20 left-4 z-10">
            <Picker onSelect={addEmoji} theme="dark" />
          </div>
        )}
      </div>
    </div>
  );
};

export default ChannelView;