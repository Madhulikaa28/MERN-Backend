import 'dotenv/config';
import cors from 'cors';
import express from 'express';
import mongoose from 'mongoose';
import { connectDB } from './config/db.js';
import authRouter from './routes/auth.js';

const app = express();
const allowedOrigins = (process.env.FRONTEND_ORIGIN ?? 'http://localhost:5173,http://127.0.0.1:5173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.use(cors({ origin: allowedOrigins }));
app.use(express.json({ limit: '10kb' }));

app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' });
});

app.use('/api/auth', authRouter);

app.use((_req, res) => {
  res.status(404).json({ message: 'The requested API endpoint was not found.' });
});

app.use((error, _req, res, _next) => {
  const status = Number.isInteger(error.status) ? error.status : 500;
  if (status >= 500) {
    console.error('API request failed:', error);
  }
  const message = status === 400
    ? 'Invalid request body.'
    : status === 413
      ? 'Request body is too large.'
      : 'An unexpected server error occurred.';
  res.status(status).json({ message });
});

async function startServer() {
  const jwtSecret = process.env.JWT_SECRET;
  const port = Number(process.env.PORT ?? 5000);

  if (!jwtSecret || jwtSecret.length < 32 || jwtSecret.startsWith('replace-this')) {
    throw new Error('Set JWT_SECRET in backend/.env to a random secret of at least 32 characters.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error('PORT must be a valid TCP port.');
  }

  await connectDB();
  app.listen(port, () => {
    console.log(`Toyland API listening on http://127.0.0.1:${port}`);
  });
}

startServer().catch((error) => {
  console.error('Could not start the Toyland API:', error.message);
  process.exitCode = 1;
});
