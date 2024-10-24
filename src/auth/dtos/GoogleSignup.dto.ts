import { IsEmail, IsString } from 'class-validator';

export class UserDtoForGoogle {
  @IsString()
  name: string;

  @IsEmail()
  email: string;

  @IsString()
  profileImage: string;
}
