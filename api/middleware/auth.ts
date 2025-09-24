import { Request, Response, NextFunction } from 'express';
import jwt, { SignOptions } from 'jsonwebtoken';
import { User, IUser } from '../models/User';

const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const JWT_EXPIRES_IN: string = process.env.JWT_EXPIRES_IN || '24h';

export interface AuthRequest extends Request {
  user?: IUser;
}

export interface JWTPayload {
  userId: string;
  username: string;
  role: string;
  iat?: number;
  exp?: number;
}

// Generate JWT token
export const generateToken = (user: IUser): string => {
  const payload: JWTPayload = {
    userId: user._id.toString(),
    username: user.username,
    role: user.role
  };
  
  const options: SignOptions = {
    expiresIn: '24h'
  };
  
  return jwt.sign(payload, JWT_SECRET, options);
};

// Verify JWT token
export const verifyToken = (token: string): JWTPayload => {
  return jwt.verify(token, JWT_SECRET) as JWTPayload;
};

// Authentication middleware
export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.status(401).json({ 
        success: false, 
        message: 'Access token required' 
      });
      return;
    }
    
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    
    try {
      const decoded = verifyToken(token);
      
      // Get user from database
      const user = await User.findById(decoded.userId).select('-passwordHash');
      
      if (!user) {
        res.status(401).json({ 
          success: false, 
          message: 'Invalid token - user not found' 
        });
        return;
      }
      
      req.user = user;
      next();
    } catch (jwtError) {
      res.status(401).json({ 
        success: false, 
        message: 'Invalid or expired token' 
      });
      return;
    }
  } catch (error) {
    console.error('Authentication error:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Internal server error during authentication' 
    });
  }
};

// Authorization middleware for admin-only routes
export const requireAdmin = (req: AuthRequest, res: Response, next: NextFunction): void => {
  if (!req.user) {
    res.status(401).json({ 
      success: false, 
      message: 'Authentication required' 
    });
    return;
  }
  
  if (req.user.role !== 'admin') {
    res.status(403).json({ 
      success: false, 
      message: 'Admin access required' 
    });
    return;
  }
  
  next();
};

// Optional authentication middleware (doesn't fail if no token)
export const optionalAuth = async (req: AuthRequest, res: Response, next: NextFunction): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.substring(7);
      
      try {
        const decoded = verifyToken(token);
        const user = await User.findById(decoded.userId).select('-passwordHash');
        
        if (user) {
          req.user = user;
        }
      } catch (jwtError) {
        // Ignore JWT errors for optional auth
      }
    }
    
    next();
  } catch (error) {
    console.error('Optional authentication error:', error);
    next(); // Continue even if there's an error
  }
};