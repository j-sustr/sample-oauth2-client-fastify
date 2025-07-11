import Fastify from 'fastify';
import cookie from '@fastify/cookie';
import session from '@fastify/session';
import crypto from 'node:crypto';

const fastify = Fastify({ logger: true });

// Fill these out with the values you got from Google
const googleClientID = 'YOUR_GOOGLE_CLIENT_ID'; // Replace with your Google Client ID
const googleClientSecret = 'YOUR_GOOGLE_CLIENT_SECRET'; // Replace with your Google Client Secret

// This is the URL we'll send the user to first to get their authorization
const authorizeURL = 'https://accounts.google.com/o/oauth2/v2/auth';

// This is Google's OpenID Connect token endpoint
const tokenURL = 'https://www.googleapis.com/oauth2/v4/token';

// Use a secure, randomly generated secret for sessions
const sessionSecret = crypto.randomBytes(32).toString('hex');

fastify.register(cookie);
fastify.register(session, {
  secret: sessionSecret,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // Use secure cookies in production
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
});

// Helper function to get the base URL
function getBaseURL(req) {
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  const protocol = req.headers['x-forwarded-proto'] || req.protocol;
  return `${protocol}://${host}/`;
}

fastify.get('/', async (req, reply) => {
  if (req.session.user_id) {
    let userInfoHtml = '';
    try {
      const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
          'Authorization': `Bearer ${req.session.access_token}`
        }
      });
      const userInfo = await userinfoResponse.json();
      userInfoHtml = `
        <h3>User Info (from Google API)</h3>
        <pre>${JSON.stringify(userInfo, null, 2)}</pre>
      `;
    } catch (error) {
      req.log.error('Error fetching user info:', error);
      userInfoHtml = '<p>Error fetching user info.</p>';
    }

    return reply.type('text/html').send(`
      <h3>Logged In</h3>
      <p>User ID: ${req.session.user_id}</p>
      <p>Email: ${req.session.email}</p>
      <p><a href="/logout">Log Out</a></p>

      <h3>ID Token Payload</h3>
      <pre>${JSON.stringify(req.session.userinfo, null, 2)}</pre>
      ${userInfoHtml}
    `);
  } else {
    return reply.type('text/html').send(`
      <h3>Not logged in</h3>
      <p><a href="/login">Log In with Google</a></p>
    `);
  }
});

fastify.get('/login', (req, reply) => {
  req.session.user_id = undefined; // Clear existing session
  const state = crypto.randomBytes(16).toString('hex');
  req.session.state = state; // Store state in session

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: googleClientID,
    redirect_uri: getBaseURL(req),
    scope: 'openid email profile', // Added 'profile' scope
    state: state
  });

  reply.redirect(`${authorizeURL}?${params.toString()}`);
});

fastify.get('/logout', async (req, reply) => {
  req.session.destroy(() => {
    reply.redirect('/');
  });
});

fastify.get('/callback', async (req, reply) => {
  const { code, state, error } = req.query;

  if (error) {
    req.log.error('OAuth error:', error);
    return reply.redirect(`/?error=${error}`);
  }

  // Verify the state matches our stored state
  if (!state || req.session.state !== state) {
    return reply.redirect('/?error=invalid_state');
  }

  try {
    const response = await fetch(tokenURL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: googleClientID,
        client_secret: googleClientSecret,
        redirect_uri: getBaseURL(req),
        code: code
      }).toString()
    });

    const data = await response.json();

    if (data.error) {
      req.log.error('Token exchange error:', data.error_description || data.error);
      return reply.redirect(`/?error=${data.error}`);
    }

    // Decode the ID token (basic decoding, for production use a robust JWT library)
    const jwt = data.id_token.split('.');
    const userinfo = JSON.parse(Buffer.from(jwt[1], 'base64url').toString()); // Use base64url

    req.session.user_id = userinfo.sub;
    req.session.email = userinfo.email;
    req.session.access_token = data.access_token;
    req.session.id_token = data.id_token;
    req.session.userinfo = userinfo; // Store decoded user info

    reply.redirect('/');
  } catch (error) {
    req.log.error('Error during token exchange:', error);
    reply.redirect('/?error=token_exchange_failed');
  }
});

const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
    console.log('Fastify server listening on port 3000');
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();