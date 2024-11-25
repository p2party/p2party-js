export const getMediaSource = () => {
  // @ts-ignore: Type not yet on all browsers
  if (window.ManagedMediaSource) {
    // @ts-ignore: Type not yet on all browsers
    return new window.ManagedMediaSource();
  } else if (window.MediaSource) {
    return new window.MediaSource();
  } else {
    throw new Error("No MediaSource API available");
  }
};
