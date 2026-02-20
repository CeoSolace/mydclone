import React from 'react';
import ChannelView from './ChannelView';

// DMView simply reuses the ChannelView component because the server
// exposes DM channels using the same API and Socket events as guild
// channels.  Having this component allows future extension specific to
// private conversations.
const DMView = () => {
  return <ChannelView />;
};

export default DMView;