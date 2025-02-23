const express = require('express');
const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const cookieParser = require('cookie-parser');
const { Client } = require('pg');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

app.use(cookieParser());
app.use(express.json());
app.use(passport.initialize());

// Setup koneksi ke PostgreSQL
const client = new Client({
  connectionString: process.env.DATABASE_URL, // Ambil dari variabel lingkungan
});
client.connect();

// Setup Passport Google OAuth 2.0
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: 'http://localhost:5000/auth/google/callback',
}, async (accessToken, refreshToken, profile, done) => {
  try {
    const user = profile._json;
    // Cek apakah user sudah ada di database, jika belum simpan
    const result = await client.query('SELECT * FROM users WHERE google_id = $1', [user.sub]);

    if (result.rows.length === 0) {
      // Simpan user baru ke database PostgreSQL
      await client.query('INSERT INTO users (google_id, username, email) VALUES ($1, $2, $3)', [user.sub, user.name, user.email]);
    }

    return done(null, user);
  } catch (error) {
    console.error(error);
    return done(error);
  }
}));

// Endpoint untuk login menggunakan Google OAuth
app.get('/auth/google', passport.authenticate('google', {
  scope: ['profile', 'email'],
}));

// Callback URL setelah login sukses
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => {
  // Set cookie untuk sesi
  res.cookie('session', req.user.sub, { httpOnly: true, secure: process.env.NODE_ENV === 'production' });
  res.redirect('http://localhost:5001'); // Redirect ke frontend
});

// Logout endpoint
app.get('/logout', (req, res) => {
  res.clearCookie('session');
  res.redirect('http://localhost:5001');
});

// Start server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});

app.get('/profile', async (req, res) => {
  const session = req.cookies.session;
  if (!session) {
    return res.status(401).json({ message: 'Not authenticated' });
  }

  try {
    const result = await client.query('SELECT * FROM users WHERE google_id = $1', [session]);
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ message: 'Internal server error' });
  }
});

