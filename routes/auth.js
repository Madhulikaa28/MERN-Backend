import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { rateLimit } from 'express-rate-limit';
import SignInEvent from '../models/SignInEvent.js';
import User from '../models/User.js';

const router = Router();
const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many attempts. Please try again in a few minutes.' },
});

function isRecord(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function validateCredentials(body, { requireName = false } = {}) {
  if (!isRecord(body)) {
    return { error: 'Please submit valid form details.' };
  }

  const email = typeof body.email === 'string' ? body.email.trim().toLowerCase() : '';
  const password = typeof body.password === 'string' ? body.password : '';

  if (!email || email.length > 254 || !emailPattern.test(email)) {
    return { error: 'Please enter a valid email address.' };
  }

  if (password.length < 8 || Buffer.byteLength(password, 'utf8') > 72) {
    return { error: 'Password must be at least 8 characters and no more than 72 bytes.' };
  }

  if (!requireName) {
    return { email, password };
  }

  const name = typeof body.name === 'string' ? body.name.trim() : '';
  if (name.length < 2 || name.length > 80) {
    return { error: 'Name must be between 2 and 80 characters.' };
  }

  return { email, password, name };
}

function isDuplicateEmailError(error) {
  return isRecord(error) && error.code === 11000;
}

async function signup(req, res, next) {
  const details = validateCredentials(req.body, { requireName: true });
  if (details.error) {
    return res.status(400).json({ message: details.error });
  }

  try {
    const existingUser = await User.findOne({ email: details.email }).select('_id');
    if (existingUser) {
      return res.status(409).json({ message: 'That email is already registered. Please sign in instead.' });
    }

    const passwordHash = await bcrypt.hash(details.password, 12);
    const user = await User.create({
      name: details.name,
      email: details.email,
      passwordHash,
    });

    return res.status(201).json({
      message: 'Your Toyland account has been created. You can now sign in.',
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    if (isDuplicateEmailError(error)) {
      return res.status(409).json({ message: 'That email is already registered. Please sign in instead.' });
    }
    return next(error);
  }
}

router.post('/signup', authRateLimit, signup);
router.post('/register', authRateLimit, signup);

router.post('/login', authRateLimit, async (req, res, next) => {
  const details = validateCredentials(req.body);
  if (details.error) {
    return res.status(400).json({ message: details.error });
  }

  try {
    const user = await User.findOne({ email: details.email }).select('+passwordHash');
    if (!user || !(await bcrypt.compare(details.password, user.passwordHash))) {
      return res.status(401).json({ message: 'Email or password is incorrect.' });
    }

    await SignInEvent.create({ user: user._id });

    const token = jwt.sign({}, process.env.JWT_SECRET, {
      subject: user.id,
      expiresIn: '1d',
    });

    return res.json({
      message: 'You are signed in. Welcome back!',
      token,
      user: { id: user.id, name: user.name, email: user.email },
    });
  } catch (error) {
    return next(error);
  }
});

export default router;
