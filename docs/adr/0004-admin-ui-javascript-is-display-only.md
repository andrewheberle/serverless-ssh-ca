# The admin UI's JavaScript only changes how times are displayed

Times are stored and rendered by the server in UTC, but admins want to read them in their own time zone, which a browser does not send and only client-side JavaScript can read. We decided to allow one same-origin script in the admin UI (`script-src 'self'`, with no inline scripts, eval or nonces) that shows times in the browser's time zone, with its UTC offset, by default, and to keep it display-only: every page must work fully without it, it never takes part in a revocation or any other action, and the landing page stays free of JavaScript.

## Considered Options

- **The server formats times in a zone the admin picks** (a cookie, defaulting to Cloudflare's IP-geolocated time zone): keeps the pages free of JavaScript, but shows a zone the admin chose or one guessed from their IP rather than their browser's, and needs a state-changing form for a display preference.
