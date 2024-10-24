import { Inject, Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-google-oauth20';
import { AuthService } from '../auth.service';

@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy) {
  constructor(
    @Inject('AUTH_SERVICE') private readonly authService: AuthService,
  ) {
    super({
      clientID: process.env.GOOGLE_CLIENT_ID as string,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET as string,
      callbackURL: process.env.GOOGLE_CALLBACK_URL as string,
      scope: ['profile', 'email'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile) {
    console.log(accessToken, refreshToken, profile);

    // this.authService.validateOAuthLogin({
    //   email: profile.emails[0]!.value,
    //   displayName: profile.displayName,
    // });

    const user = await this.authService.validateUser({
      name: profile.displayName,
      email: profile.emails[0].value,
      profileImage: profile.photos[0].value,
    });
    console.log('Validate');
    console.log(user);
    return user || null;
  }
}
