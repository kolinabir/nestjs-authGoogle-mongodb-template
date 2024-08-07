/* eslint-disable prettier/prettier */
import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/SignUpDto.dto';
import { LoginDto } from './dtos/loginDto.dto';
import { RefreshTokenDto } from './dtos/RefreshTokenDto.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  async signUp(@Body() signUpData: SignUpDto) {
    return this.authService.singup(signUpData);
  }

  @Post('login')
  async login(@Body() loginData: LoginDto) {
    return this.authService.login(loginData);
  }

  @Post('refresh')
  async refreshToken(@Body() refreshTokenData: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenData.refreshToken);
  }
}
