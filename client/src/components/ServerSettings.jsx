import React, { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useAuth } from '../App';

// Guild/server settings page.  Only the owner can access this page.  Allows
// updating the guild name and image.
const ServerSettings = () => {
  const { guildId } = useParams();
  const { token, user } = useAuth();
  const [guild, setGuild] = useState(null);
  const [name, setName] = useState('');
  const [imageFile, setImageFile] = useState(null);
  const [message, setMessage] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    // Fetch guilds and find this one
    fetch('/api/guilds', { headers: { Authorization: `Bearer ${token}` } })
      .then((res) => res.json())
      .then((data) => {
        const g = data.find((x) => x._id === guildId);
        setGuild(g);
        setName(g?.name || '');
      });
  }, [guildId, token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      if (name) formData.append('name', name);
      if (imageFile) formData.append('image', imageFile);
      const res = await fetch(`/api/guilds/${guildId}/settings`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Update failed');
      setGuild(data.guild);
      setMessage('Guild updated');
    } catch (err) {
      setMessage(err.message);
    }
  };

  if (!guild) return <div className="p-4 text-gray-400">Loading…</div>;
  if (guild.owner !== user._id) return <div className="p-4 text-red-400">Only the owner can edit settings.</div>;

  return (
    <div className="flex flex-col items-center p-6 text-white">
      <button
        onClick={() => navigate(-1)}
        className="mb-4 self-start text-blue-400 hover:underline"
      >
        ← Back
      </button>
      <h1 className="text-2xl font-bold mb-4">Guild Settings</h1>
      <form onSubmit={handleSubmit} className="bg-gray-900 p-6 rounded shadow w-96">
        <label className="block mb-2">Guild Name</label>
        <input
          type="text"
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full p-2 mb-4 rounded bg-gray-700 text-white"
        />
        <label className="block mb-2">Guild Image</label>
        <input
          type="file"
          accept="image/*"
          onChange={(e) => setImageFile(e.target.files[0])}
          className="mb-4"
        />
        <button
          type="submit"
          className="w-full bg-blue-600 hover:bg-blue-700 p-2 rounded"
        >
          Save Changes
        </button>
        {message && (
          <p className="mt-2 text-center text-sm text-green-400">{message}</p>
        )}
      </form>
    </div>
  );
};

export default ServerSettings;