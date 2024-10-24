import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { User, UserSchema } from './schemas/user.schema';
import {
  RefreshToken,
  RefreshTokenSchema,
} from './schemas/refresh-token.schema';
import { ResetToken, ResetTokenSchema } from './schemas/reset-token.schema';
import { MailService } from 'src/services/mail.service';
import { GoogleStrategy } from './utils/GoogleStrategy';
import { SessionSerializer } from './utils/Serializer';

@Module({
  imports: [
    MongooseModule.forFeature([
      {
        name: User.name,
        schema: UserSchema,
      },
      {
        name: RefreshToken.name,
        schema: RefreshTokenSchema,
      },
      {
        name: ResetToken.name,
        schema: ResetTokenSchema,
      },
    ]),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    MailService,
    GoogleStrategy,
    SessionSerializer,
    {
      provide: 'AUTH_SERVICE',
      useClass: AuthService,
    },
  ],
})
export class AuthModule {}
