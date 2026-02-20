import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';

// Home page displays the list of guilds and direct message threads available
// to the user.  From here users can create new guilds, start DMs and access
// settings.
const Home = () => {
  const { token, user, logout } = useAuth();
  const [guilds, setGuilds] = useState([]);
  const [dms, setDms] = useState([]);
  const [creatingGuild, setCreatingGuild] = useState(false);
  const [guildName, setGuildName] = useState('');
  const [dmEmail, setDmEmail] = useState('');
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Fetch guilds
    fetch('/api/guilds', { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => setGuilds(data));
    // Fetch DMs
    fetch('/api/dms', { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => setDms(data));
  }, [token]);

  const handleCreateGuild = async () => {
    if (!guildName.trim()) return;
    try {
      const res = await fetch('/api/guilds', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ name: guildName }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Create guild failed');
      setGuilds((g) => [...g, data]);
      setGuildName('');
      setCreatingGuild(false);
    } catch (err) {
      setError(err.message);
    }
  };

  const handleCreateDm = async () => {
    if (!dmEmail.trim()) return;
    try {
      const res = await fetch('/api/dms', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ otherEmail: dmEmail }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Create DM failed');
      setDms((d) => [...d.filter((dm) => dm._id !== data._id), data]);
      setDmEmail('');
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="flex h-screen">
      {/* Sidebar */}
      <div className="w-64 bg-gray-900 p-4 overflow-y-auto flex flex-col">
        <div className="mb-4">
          <h2 className="text-lg font-bold">Servers</h2>
          <ul className="space-y-1 mt-2">
            {guilds.map((g) => (
              <li key={g._id}>
                <Link
                  to={`/guild/${g._id}`}
                  className="block px-3 py-2 rounded hover:bg-gray-700"
                >
                  {g.name}
                </Link>
              </li>
            ))}
          </ul>
          {/* Create guild button */}
          {creatingGuild ? (
            <div className="mt-2">
              <input
                type="text"
                value={guildName}
                onChange={(e) => setGuildName(e.target.value)}
                placeholder="Guild name"
                className="w-full p-2 mb-1 rounded bg-gray-700 text-white"
              />
              <button
                onClick={handleCreateGuild}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white p-2 rounded mb-2"
              >
                Create
              </button>
              <button
                onClick={() => setCreatingGuild(false)}
                className="w-full bg-gray-600 hover:bg-gray-700 text-white p-2 rounded"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button
              onClick={() => setCreatingGuild(true)}
              className="w-full mt-2 bg-green-600 hover:bg-green-700 text-white p-2 rounded"
            >
              + Create Guild
            </button>
          )}
        </div>
        {/* DMs */}
        <div className="mb-4">
          <h2 className="text-lg font-bold">Direct Messages</h2>
          <ul className="space-y-1 mt-2">
            {dms.map((dm) => (
              <li key={dm._id}>
                <Link
                  to={`/dm/${dm._id}`}
                  className="block px-3 py-2 rounded hover:bg-gray-700"
                >
                  DM: {dm.participants
                    .filter((p) => p !== user._id)
                    .map((p) => p)
                    .join(', ')}
                </Link>
              </li>
            ))}
          </ul>
          <div className="mt-2">
            <input
              type="email"
              value={dmEmail}
              onChange={(e) => setDmEmail(e.target.value)}
              placeholder="Start DM via email"
              className="w-full p-2 mb-2 rounded bg-gray-700 text-white"
            />
            <button
              onClick={handleCreateDm}
              className="w-full bg-purple-600 hover:bg-purple-700 text-white p-2 rounded"
            >
              + Start DM
            </button>
          </div>
        </div>
        {/* Settings and logout */}
        <div className="mt-auto">
          <Link
            to="/settings"
            className="block mb-2 px-3 py-2 rounded bg-gray-700 hover:bg-gray-600 text-white text-center"
          >
            User Settings
          </Link>
          <button
            onClick={logout}
            className="w-full bg-red-600 hover:bg-red-700 text-white p-2 rounded"
          >
            Logout
          </button>
        </div>
        {error && (
          <p className="mt-2 text-red-400 text-sm">{error}</p>
        )}
      </div>
      {/* Placeholder main content */}
      <div className="flex-1 flex items-center justify-center text-gray-400">
        <p>Select a server or DM to begin.</p>
      </div>
    </div>
  );
};

export default Home;