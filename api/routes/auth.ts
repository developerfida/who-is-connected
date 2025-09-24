/**
 * Authentication API routes
 * Handle user registration, login, token management, etc.
 */
import { Router, type Request, type Response } from 'express';
import Joi from 'joi';
import { User } from '../models/User';
import { generateToken, authenticate, AuthRequest } from '../middleware/auth';

const router = Router();

// Validation schemas
const loginSchema = Joi.object({
  username: Joi.string().min(3).max(50).required(),
  password: Joi.string().min(6).required()
});

const registerSchema = Joi.object({
  username: Joi.string().min(3).max(50).required(),
  password: Joi.string().min(6).required(),
  role: Joi.string().valid('admin', 'user').default('user')
});

/**
 * User Registration
 * POST /api/auth/register
 */
router.post('/register', async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body
    const { error, value } = registerSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    const { username, password, role } = value;

    // Check if user already exists
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      res.status(409).json({
        success: false,
        message: 'Username already exists'
      });
      return;
    }

    // Create new user
    const user = new User({
      username,
      passwordHash: password, // Will be hashed by pre-save hook
      role
    });

    await user.save();

    // Generate token
    const token = generateToken(user);

    res.status(201).json({
      success: true,
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        createdAt: user.createdAt
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during registration'
    });
  }
});

/**
 * User Login
 * POST /api/auth/login
 */
router.post('/login', async (req: Request, res: Response): Promise<void> => {
  try {
    // Validate request body
    const { error, value } = loginSchema.validate(req.body);
    if (error) {
      res.status(400).json({
        success: false,
        message: 'Validation error',
        details: error.details[0].message
      });
      return;
    }

    const { username, password } = value;

    // Find user by username
    const user = await User.findOne({ username });
    if (!user) {
      res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
      return;
    }

    // Check password
    const isPasswordValid = await user.comparePassword(password);
    if (!isPasswordValid) {
      res.status(401).json({
        success: false,
        message: 'Invalid username or password'
      });
      return;
    }

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    // Generate token
    const token = generateToken(user);

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        role: user.role,
        lastLogin: user.lastLogin
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during login'
    });
  }
});

/**
 * User Logout
 * POST /api/auth/logout
 */
router.post('/logout', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // In a stateless JWT system, logout is handled client-side by removing the token
    // Here we just confirm the logout
    res.json({
      success: true,
      message: 'Logout successful'
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during logout'
    });
  }
});

/**
 * Get Current User Profile
 * GET /api/auth/profile
 */
router.get('/profile', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (!req.user) {
      res.status(401).json({
        success: false,
        message: 'User not authenticated'
      });
      return;
    }

    res.json({
      success: true,
      user: {
        id: req.user._id,
        username: req.user.username,
        role: req.user.role,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      }
    });
  } catch (error) {
    console.error('Profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error while fetching profile'
    });
  }
});

/**
 * Verify Token
 * GET /api/auth/verify
 */
router.get('/verify', authenticate, async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    res.json({
      success: true,
      message: 'Token is valid',
      user: {
        id: req.user?._id,
        username: req.user?.username,
        role: req.user?.role
      }
    });
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error during token verification'
    });
  }
});

export default router;
