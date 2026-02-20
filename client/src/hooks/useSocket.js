import { useEffect, useRef } from 'react';
import { io } from 'socket.io-client';

// Hook to create and manage a Socket.IO client connection.  The socket
// instance persists across re-renders and is disconnected when the
// component using this hook unmounts.  It takes a JWT token for
// authentication.

export default function useSocket(token) {
  const socketRef = useRef(null);
  useEffect(() => {
    if (!token) return;
    // Create the socket with auth token.  Pass via query and auth fields
    const socket = io({
      auth: { token },
      query: { token },
    });
    socketRef.current = socket;
    return () => {
      socket.disconnect();
    };
  }, [token]);
  return socketRef.current;
}