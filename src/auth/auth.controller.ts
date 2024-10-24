/* eslint-disable prettier/prettier */
import { Body, Controller, Get, Post, Put, Req, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/SignUpDto.dto';
import { LoginDto } from './dtos/loginDto.dto';
import { RefreshTokenDto } from './dtos/RefreshTokenDto.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthGuard } from 'src/guard/auth.guard';
import { ForgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { GoogleAuthGuard } from './utils/Guards';

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

  @UseGuards(AuthGuard)
  @Put('change-password')
  async changePassword(
    @Body() changePasswordData: ChangePasswordDto,
    @Req() req,
  ) {
    return this.authService.changePassword(
      req.userId,
      changePasswordData.oldPassword,
      changePasswordData.newPassword,
    );
  }

  @Post('forgot-password')
  async forgotPassword(@Body() forgotPasswordData: ForgotPasswordDto) {
    return this.authService.forgotPassword(forgotPasswordData.email);
  }

  @Post('reset-password')
  async resetPassword(@Body() resetPasswordData: ResetPasswordDto) {
    return this.authService.resetPassword(
      resetPasswordData.newPassword,
      resetPasswordData.resetToken,
    );
  }

  @Get('google-login')
  @UseGuards(GoogleAuthGuard)
  handleLogin() {}

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard) 
  handleRedirect() {}
}
