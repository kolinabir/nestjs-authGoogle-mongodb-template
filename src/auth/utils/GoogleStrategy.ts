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
      clientID:
        '66639275888-v8a6cr9sgqk0d6jgnkf883qk277090tn.apps.googleusercontent.com',
      clientSecret: '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',
      callbackURL: 'http://localhost:4000/auth/google/redirect',
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
