import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { Request } from 'express';

export class RequestWithUser extends Request {
  userId: string;
  role: string;
}

@Injectable()
export class AuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request: RequestWithUser = context.switchToHttp().getRequest();
    const token = request.headers['authorization']?.split(' ')[1];
    if (!token) {
      throw new UnauthorizedException('Invalid Token');
    }
    try {
      const payload = this.jwtService.verify(token);
      request.userId = payload.id;
    } catch (error) {
      Logger.error(error.message);
      throw new UnauthorizedException('Invalid Token');
    }

    return true;
  }
}
