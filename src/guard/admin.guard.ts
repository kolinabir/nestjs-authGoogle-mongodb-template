import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { Request } from 'express';
import { Reflector } from '@nestjs/core';
import { Roles_Key } from 'src/auth/decorators/roles.decorator';
import { RequestWithUser } from './auth.guard';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AdminGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    private jwtService: JwtService,
  ) {}
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
      request.role = payload.role;
    } catch (error) {
      Logger.error(error.message);
      throw new UnauthorizedException('Invalid Token');
    }
    const requiredRoles = this.reflector.get(Roles_Key, context.getHandler());
    const userRole = request.role;
    if (!requiredRoles.includes(userRole)) {
      throw new UnauthorizedException('Invalid Role');
    }
    return true;
  }
}
