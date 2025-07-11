import Fastify from 'fastify';
import fastifyCookie from '@fastify/cookie';
import fastifySession from '@fastify/session';
import dotenv from 'dotenv';
import axios from 'axios';

// Load environment variables from .env file
dotenv.config();

const fastify = Fastify({
  logger: true
});

// Register cookie and session plugins
// For production, you should use a strong, randomly generated secret
fastify.register(fastifyCookie);
fastify.register(fastifySession, {
  secret: process.env.SESSION_SECRET || 'a-very-secret-key-that-should-be-randomly-generated-in-production',
  cookie: {
    secure: process.env.NODE_ENV === 'production' // Set to true in production for HTTPS
  }
});

// Fill these out with the values you got from Github
const githubClientID = process.env.GITHUB_CLIENT_ID || '';
const githubClientSecret = process.env.GITHUB_CLIENT_SECRET || '';

// This is the URL we'll send the user to first to get their authorization
const authorizeURL = 'https://github.com/login/oauth/authorize';

// This is the endpoint our server will request an access token from
const tokenURL = 'https://github.com/login/oauth/access_token';

// This is the Github base URL we can use to make authenticated API requests
const apiURLBase = 'https://api.github.com/';

// Base URL for this application, used as the redirect URL
// In a real application, this would be your deployed domain
const baseURL = process.env.BASE_URL || 'http://localhost:3000';

// Helper function to make API requests to GitHub
async function apiRequest(url: string, postData: any = null, accessToken: string | null = null) {
  const headers: Record<string, string> = {
    'Accept': 'application/vnd.github.v3+json, application/json',
    'User-Agent': 'https://example-app.com/' // Replace with your app's user agent
  };

  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  try {
    const response = await axios({
      method: postData ? 'POST' : 'GET',
      url: url,
      data: postData,
      headers: headers,
    });
    return response.data;
  } catch (error: any) {
    fastify.log.error(`API Request Error to ${url}: ${error.message}`);
    throw new Error(`Failed to make API request: ${error.message}`);
  }
}

// Root route - displays login/logout status
fastify.get('/', async (request, reply) => {
  if (request.session.get('access_token')) {
    return reply.send(`
      <h3>Logged In</h3>
      <p><a href="/repos">View Repos</a></p>
      <p><a href="/logout">Log Out</a></p>
    `);
  } else {
    return reply.send(`
      <h3>Not logged in</h3>
      <p><a href="/login">Log In</a></p>
    `);
  }
});

// Login route - redirects to GitHub authorization page
fastify.get('/login', async (request, reply) => {
  request.session.delete('access_token');

  // Generate a random hash and store in the session
  const state = crypto.randomBytes(16).toString('hex');
  request.session.set('state', state);

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: githubClientID,
    redirect_uri: baseURL,
    scope: 'user public_repo',
    state: state
  });

  return reply.redirect(`${authorizeURL}?${params.toString()}`);
});

// Logout route - clears session and redirects to home
fastify.get('/logout', async (request, reply) => {
  request.session.delete('access_token');
  request.session.delete('state');
  return reply.redirect('/');
});

// GitHub OAuth callback route
fastify.get('/', async (request, reply) => {
  const { code, state, error } = request.query as { code?: string, state?: string, error?: string };

  if (error) {
    fastify.log.error(`GitHub OAuth Error: ${error}`);
    return reply.send(`GitHub OAuth Error: ${error}`);
  }

  if (code) {
    // Verify the state matches our stored state
    if (!state || request.session.get('state') !== state) {
      fastify.log.error('Invalid state parameter in OAuth callback');
      return reply.redirect(`${baseURL}?error=invalid_state`);
    }

    try {
      // Exchange the auth code for an access token
      const tokenResponse = await apiRequest(tokenURL, {
        grant_type: 'authorization_code',
        client_id: githubClientID,
        client_secret: githubClientSecret,
        redirect_uri: baseURL,
        code: code
      });

      if (tokenResponse && tokenResponse.access_token) {
        request.session.set('access_token', tokenResponse.access_token);
        // Clear the state after successful use
        request.session.delete('state');
        return reply.redirect('/');
      } else {
        fastify.log.error('No access token received from GitHub');
        return reply.send('Failed to get access token.');
      }
    } catch (err: any) {
      fastify.log.error(`Error exchanging code for token: ${err.message}`);
      return reply.send('Error during token exchange.');
    }
  } else {
    // If no code and no action, serve the root page content
    if (request.session.get('access_token')) {
      return reply.send(`
        <h3>Logged In</h3>
        <p><a href="/repos">View Repos</a></p>
        <p><a href="/logout">Log Out</a></p>
      `);
    } else {
      return reply.send(`
        <h3>Not logged in</h3>
        <p><a href="/login">Log In</a></p>
      `);
    }
  }
});


// Repos route - fetches and displays user repositories
fastify.get('/repos', async (request, reply) => {
  const accessToken = request.session.get('access_token');

  if (!accessToken) {
    return reply.redirect('/login'); // Redirect to login if not authenticated
  }

  try {
    // Find all repos created by the authenticated user
    const repos = await apiRequest(
      `${apiURLBase}user/repos?${new URLSearchParams({
        sort: 'created',
        direction: 'desc'
      }).toString()}`,
      null, // No POST data
      accessToken
    );

    let repoListHtml = '<ul>';
    if (Array.isArray(repos)) {
      repos.forEach((repo: any) => {
        repoListHtml += `<li><a href="${repo.html_url}">${repo.name}</a></li>`;
      });
    } else {
      repoListHtml += '<li>No repositories found or an error occurred.</li>';
      fastify.log.warn('GitHub API returned unexpected format for repos:', repos);
    }
    repoListHtml += '</ul>';

    return reply.send(`
      <h3>Your Repositories</h3>
      ${repoListHtml}
      <p><a href="/">Back to Home</a></p>
    `);
  } catch (err: any) {
    fastify.log.error(`Error fetching repos: ${err.message}`);
    return reply.send('Error fetching repositories.');
  }
});


// Start the server
const start = async () => {
  try {
    await fastify.listen({ port: 3000 });
    fastify.log.info(`Server listening on ${fastify.server.address()}`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();