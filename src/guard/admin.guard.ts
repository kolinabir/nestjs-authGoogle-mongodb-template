import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { Roles_Key } from 'src/auth/decorators/roles.decorator';
import { JwtService } from '@nestjs/jwt';

export interface RequestWithUser extends Request {
  userId: string;
  role: string;
}

export interface JwtPayload {
  id: string;
  role: string;
  email?: string;
}

@Injectable()
export class AdminGuard implements CanActivate {
  private readonly logger = new Logger(AdminGuard.name);

  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: RequestWithUser = context.switchToHttp().getRequest();

    // Extract and validate token
    const authHeader = request.headers['authorization'];
    if (!authHeader) {
      throw new UnauthorizedException({
        status: 401,
        message: 'No authorization token provided',
        authenticated: false,
      });
    }

    const [bearer, token] = authHeader.split(' ');
    if (bearer !== 'Bearer' || !token) {
      throw new UnauthorizedException({
        status: 401,
        message: 'Invalid authorization header format',
        authenticated: false,
      });
    }

    // Verify JWT token
    try {
      const payload = this.jwtService.verify(token) as JwtPayload;

      // Attach user info to request
      request.userId = payload.id;
      request.role = payload.role;

      // Get required roles for the route
      const requiredRoles = this.reflector.get(Roles_Key, context.getHandler());

      // If no roles are specified, allow access
      if (!requiredRoles || requiredRoles.length === 0) {
        return true;
      }

      // Check if user has required role
      if (!requiredRoles.includes(payload.role)) {
        throw new ForbiddenException({
          status: 403,
          message: 'Insufficient permissions',
          authenticated: true,
          authorized: false,
          requiredRoles,
          userRole: payload.role,
        });
      }

      return true;
    } catch (error) {
      this.logger.error(`Authentication error: ${error.message}`, error.stack);

      // Handle different types of JWT errors
      if (error.name === 'JsonWebTokenError') {
        throw new UnauthorizedException({
          status: 401,
          message: 'Invalid token',
          authenticated: false,
          error: 'TOKEN_INVALID',
        });
      }

      if (error.name === 'TokenExpiredError') {
        throw new UnauthorizedException({
          status: 401,
          message: 'Token has expired',
          authenticated: false,
          error: 'TOKEN_EXPIRED',
        });
      }

      // If it's already a ForbiddenException, rethrow it
      if (error instanceof ForbiddenException) {
        throw error;
      }

      // For any other errors
      throw new UnauthorizedException({
        status: 401,
        message: 'Authentication failed',
        authenticated: false,
        error: 'AUTHENTICATION_FAILED',
      });
    }
  }
}
