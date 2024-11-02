import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<Request>();

    // Check if user exists in the request (set by Passport session)
    if (!request.user) {
      throw new UnauthorizedException({
        authenticated: false,
        message: 'User not authenticated',
      });
    }

    return true;
  }
}
