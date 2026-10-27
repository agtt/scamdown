// Login popup lands here: hand the code back to the page that opened it, then close.
// BroadcastChannel works even when the login provider cut the link to window.opener.
new BroadcastChannel("scamdown-oauth").postMessage(location.search);
history.replaceState(null, "", location.pathname);
setTimeout(() => window.close(), 300);
