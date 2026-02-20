import React, { useState, useEffect, createContext, useContext } from 'react';
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom';
import Login from './components/Login';
import Register from './components/Register';
import Home from './components/Home';
import GuildView from './components/GuildView';
import ChannelView from './components/ChannelView';
import DMView from './components/DMView';
import UserSettings from './components/UserSettings';
import ServerSettings from './components/ServerSettings';

// Simple authentication context.  It holds the JWT token and user info.
const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

function App() {
  const [token, setToken] = useState(() => localStorage.getItem('token'));
  const [user, setUser] = useState(null);
  const navigate = useNavigate();

  // Whenever the token changes, fetch the current user
  useEffect(() => {
    if (token) {
      fetch('/api/me', {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((res) => res.ok ? res.json() : Promise.reject())
        .then((u) => setUser(u))
        .catch(() => {
          setToken(null);
          setUser(null);
          localStorage.removeItem('token');
        });
    }
  }, [token]);

  // Login helper to store token
  const login = (jwt) => {
    setToken(jwt);
    localStorage.setItem('token', jwt);
  };
  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    navigate('/login');
  };

  const authValue = { token, user, login, logout, setUser };

  return (
    <AuthContext.Provider value={authValue}>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route
          path="/"
          element={token ? <Home /> : <Navigate to="/login" replace />}
        />
        <Route
          path="/guild/:guildId"
          element={token ? <GuildView /> : <Navigate to="/login" replace />}
        />
        <Route
          path="/channel/:channelId"
          element={token ? <ChannelView /> : <Navigate to="/login" replace />}
        />
        <Route
          path="/dm/:dmId"
          element={token ? <DMView /> : <Navigate to="/login" replace />}
        />
        <Route
          path="/settings"
          element={token ? <UserSettings /> : <Navigate to="/login" replace />}
        />
        <Route
          path="/guild/:guildId/settings"
          element={token ? <ServerSettings /> : <Navigate to="/login" replace />}
        />
      </Routes>
    </AuthContext.Provider>
  );
}

export default App;