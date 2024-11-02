/* eslint-disable prettier/prettier */
import {
  Body,
  Controller,
  Get,
  Post,
  Put,
  Req,
  Request,
  Res,
  UseGuards,
} from '@nestjs/common';
import { Response } from 'express';
import {} from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignUpDto } from './dtos/SignUpDto.dto';
import { LoginDto } from './dtos/loginDto.dto';
import { RefreshTokenDto } from './dtos/RefreshTokenDto.dto';
import { ChangePasswordDto } from './dtos/change-password.dto';
import { AuthGuard } from 'src/guard/auth.guard';
import { ForgotPasswordDto } from './dtos/forgotPassword.dto';
import { ResetPasswordDto } from './dtos/reset-password.dto';
import { GoogleAuthGuard } from './utils/Guards';
import { User } from './schemas/user.schema';

interface CustomRequest extends Request {
  user?: {
    _id: string;
  };
}

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
  handleLogin() {
    // Guard will redirect to Google
  }

  @Get('google/redirect')
  @UseGuards(GoogleAuthGuard)
  async googleRedirect(@Req() req, @Res() res: Response) {
    // After successful authentication
    res.redirect('http://localhost:3000');
  }

  @Get('me')
  async getCurrentUser(@Request() req) {
    if (!req.user) {
      return { authenticated: false };
    }
    return { authenticated: true, user: req.user };
  }

  @Get('logout')
  logout(@Request() req, @Res() res: Response) {
    req.session.destroy(() => {
      res.clearCookie('connect.sid'); // Clear the session cookie
      res.redirect('http://localhost:3000'); // Redirect to frontend
    });
  }

  @Get('protected')
  @UseGuards(AuthGuard)
  protectedRoute(@Request() req: CustomRequest) {
    return {
      message: 'This is a protected route, only logged in users can access it',
      user: req.user,
    };
  }
}
