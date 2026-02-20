import React, { useEffect, useState } from 'react';
import { useParams, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';
import useSocket from '../hooks/useSocket';

// Guild view component.  Displays categories and channels for a specific
// guild, allows creation of categories and channels (if user has manage
// permission), and provides a link to guild settings for the owner.  It also
// joins the guild via Socket.IO to receive real‑time updates.
const GuildView = () => {
  const { guildId } = useParams();
  const { token, user } = useAuth();
  const socket = useSocket(token);
  const [guild, setGuild] = useState(null);
  const [categories, setCategories] = useState([]);
  const [channelsByCat, setChannelsByCat] = useState({});
  const [creatingCategory, setCreatingCategory] = useState(false);
  const [categoryName, setCategoryName] = useState('');
  const [creatingChannelFor, setCreatingChannelFor] = useState(null);
  const [channelName, setChannelName] = useState('');
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  // Fetch guild data
  useEffect(() => {
    if (!token) return;
    fetch(`/api/guilds`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((data) => {
        const g = data.find((x) => x._id === guildId);
        setGuild(g);
      });
    // Load categories
    fetch(`/api/guilds/${guildId}/categories`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.json())
      .then((cats) => {
        setCategories(cats);
        // For each category, fetch channels
        cats.forEach((cat) => {
          fetch(`/api/categories/${cat._id}/channels`, {
            headers: { Authorization: `Bearer ${token}` },
          })
            .then((res) => res.json())
            .then((chans) => {
              setChannelsByCat((prev) => ({ ...prev, [cat._id]: chans }));
            });
        });
      });
  }, [guildId, token]);

  // Join guild via socket to load channels and categories in real time
  useEffect(() => {
    if (!socket) return;
    socket.emit('joinGuild', guildId);
    const onData = ({ categories: cats, channels }) => {
      setCategories(cats);
      const byCat = {};
      cats.forEach((cat) => {
        byCat[cat._id] = channels.filter((c) => String(c.category) === String(cat._id));
      });
      // Top level guild channels (no category) are keyed under null
      byCat['root'] = channels.filter((c) => !c.category);
      setChannelsByCat(byCat);
    };
    socket.on('guildData', onData);
    return () => {
      socket.off('guildData', onData);
    };
  }, [socket, guildId]);

  const hasManage = guild && (guild.owner === user._id);

  const handleCreateCategory = async () => {
    if (!categoryName.trim()) return;
    try {
      const res = await fetch(`/api/guilds/${guildId}/categories`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ name: categoryName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Create category failed');
      setCategories((prev) => [...prev, data]);
      setCreatingCategory(false);
      setCategoryName('');
    } catch (err) {
      setError(err.message);
    }
  };

  const handleCreateChannel = async (categoryId) => {
    if (!channelName.trim()) return;
    try {
      const res = await fetch(`/api/categories/${categoryId}/channels`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ name: channelName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Create channel failed');
      setChannelsByCat((prev) => ({ ...prev, [categoryId]: [...(prev[categoryId] || []), data] }));
      setCreatingChannelFor(null);
      setChannelName('');
    } catch (err) {
      setError(err.message);
    }
  };

  if (!guild) {
    return <div className="p-4 text-gray-400">Loading...</div>;
  }

  return (
    <div className="flex h-screen">
      {/* Sidebar: categories and channels */}
      <div className="w-64 bg-gray-900 p-4 overflow-y-auto">
        <h2 className="text-xl font-bold mb-2">{guild.name}</h2>
        <button
          onClick={() => navigate('/')}
          className="mb-3 text-sm text-blue-400 hover:underline"
        >
          ← Back
        </button>
        {hasManage && (
          <button
            onClick={() => navigate(`/guild/${guildId}/settings`)}
            className="w-full mb-3 bg-gray-700 hover:bg-gray-600 text-white p-2 rounded"
          >
            Guild Settings
          </button>
        )}
        <ul className="space-y-2">
          {/* Display uncategorised channels */}
          {channelsByCat['root'] && channelsByCat['root'].length > 0 && (
            <li>
              <p className="text-sm font-semibold uppercase text-gray-400 mb-1">Channels</p>
              <ul className="space-y-1 mb-2">
                {channelsByCat['root'].map((ch) => (
                  <li key={ch._id}>
                    <Link
                      to={`/channel/${ch._id}`}
                      className="block px-3 py-1 rounded hover:bg-gray-700"
                    >
                      # {ch.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </li>
          )}
          {categories.map((cat) => (
            <li key={cat._id}>
              <p className="text-sm font-semibold uppercase text-gray-400 mb-1">
                {cat.name}
                {hasManage && (
                  <button
                    onClick={() => setCreatingChannelFor(cat._id)}
                    className="ml-2 text-green-400 hover:text-green-300"
                    title="Create channel"
                  >
                    +
                  </button>
                )}
              </p>
              <ul className="space-y-1 mb-2 ml-2">
                {(channelsByCat[cat._id] || []).map((ch) => (
                  <li key={ch._id}>
                    <Link
                      to={`/channel/${ch._id}`}
                      className="block px-3 py-1 rounded hover:bg-gray-700"
                    >
                      # {ch.name}
                    </Link>
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
        {hasManage && creatingCategory && (
          <div className="mt-3">
            <input
              type="text"
              value={categoryName}
              onChange={(e) => setCategoryName(e.target.value)}
              placeholder="Category name"
              className="w-full p-2 mb-2 rounded bg-gray-700 text-white"
            />
            <button
              onClick={handleCreateCategory}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded mb-1"
            >
              Create Category
            </button>
            <button
              onClick={() => setCreatingCategory(false)}
              className="w-full bg-gray-600 hover:bg-gray-700 text-white p-2 rounded"
            >
              Cancel
            </button>
          </div>
        )}
        {hasManage && !creatingCategory && (
          <button
            onClick={() => setCreatingCategory(true)}
            className="w-full mt-3 bg-green-600 hover:bg-green-700 text-white p-2 rounded"
          >
            + Create Category
          </button>
        )}
        {/* Create channel form for a specific category */}
        {creatingChannelFor && (
          <div className="mt-3">
            <input
              type="text"
              value={channelName}
              onChange={(e) => setChannelName(e.target.value)}
              placeholder="Channel name"
              className="w-full p-2 mb-2 rounded bg-gray-700 text-white"
            />
            <button
              onClick={() => handleCreateChannel(creatingChannelFor)}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded mb-1"
            >
              Create Channel
            </button>
            <button
              onClick={() => setCreatingChannelFor(null)}
              className="w-full bg-gray-600 hover:bg-gray-700 text-white p-2 rounded"
            >
              Cancel
            </button>
          </div>
        )}
        {error && (
          <p className="mt-2 text-red-400 text-sm">{error}</p>
        )}
      </div>
      {/* Main area placeholder */}
      <div className="flex-1 flex items-center justify-center text-gray-400">
        <p>Select a channel</p>
      </div>
    </div>
  );
};

export default GuildView;