import React, { useState } from 'react';
import { useAuth } from '../App';
import { useNavigate } from 'react-router-dom';

// User settings page.  Users can change their display name and avatar.
const UserSettings = () => {
  const { token, user, setUser } = useAuth();
  const [username, setUsername] = useState(user?.username || '');
  const [avatarFile, setAvatarFile] = useState(null);
  const [message, setMessage] = useState(null);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const formData = new FormData();
      if (username) formData.append('username', username);
      if (avatarFile) formData.append('avatar', avatarFile);
      const res = await fetch('/api/user/settings', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData,
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Update failed');
      setUser((prev) => ({ ...prev, ...data.user }));
      setMessage('Profile updated');
    } catch (err) {
      setMessage(err.message);
    }
  };

  return (
    <div className="flex flex-col items-center p-6 text-white">
      <button
        onClick={() => navigate(-1)}
        className="mb-4 self-start text-blue-400 hover:underline"
      >
        ← Back
      </button>
      <h1 className="text-2xl font-bold mb-4">User Settings</h1>
      <form onSubmit={handleSubmit} className="bg-gray-900 p-6 rounded shadow w-96">
          <label className="block mb-2">Display Name</label>
          <input
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full p-2 mb-4 rounded bg-gray-700 text-white"
          />
          <label className="block mb-2">Avatar</label>
          <input
            type="file"
            accept="image/*"
            onChange={(e) => setAvatarFile(e.target.files[0])}
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

export default UserSettings;