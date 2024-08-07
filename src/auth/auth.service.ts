import {
  BadRequestException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { SignUpDto } from './dtos/SignUpDto.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './schemas/user.schema';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { LoginDto } from './dtos/loginDto.dto';
import { JwtService } from '@nestjs/jwt';
import { RefreshToken } from './schemas/refresh-token.schema';
import { v4 as uuidv4 } from 'uuid';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(RefreshToken.name)
    private refreshTokenModel: Model<RefreshToken>,
    @InjectModel(User.name) private userModel: Model<User>,
    private jwtService: JwtService,
  ) {}
  async singup(signUpdata: SignUpDto) {
    const checkEmailInUse = await this.userModel.findOne({
      email: signUpdata.email,
    });
    if (checkEmailInUse) {
      throw new BadRequestException('Email already in use');
    }
    const hashedPassword = await bcrypt.hash(signUpdata.password, 12);
    const user = await this.userModel.create({
      ...signUpdata,
      password: hashedPassword,
    });
    if (!user) {
      throw new Error('Failed');
    }
    const { password, ...userWithoutPassword } = user.toObject();
    return userWithoutPassword;
  }

  async login(loginData: LoginDto) {
    const { email, password } = loginData;
    const checkUserExist = await this.userModel.findOne({ email });
    if (!checkUserExist) {
      throw new UnauthorizedException("Email doesn't exist");
    }
    const passwordMatch = await bcrypt.compare(
      password,
      checkUserExist.password,
    );
    if (!passwordMatch) {
      throw new UnauthorizedException('Wrong password');
    }
    const token = this.jwtService.sign(
      {
        id: checkUserExist._id,
        role: checkUserExist.role,
      },
      {
        expiresIn: '1h',
      },
    );
    const refreshToken = uuidv4();
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    //store to db
    const addToDb = await this.refreshTokenModel.create({
      token: refreshToken,
      userId: checkUserExist._id,
      expiryDate,
    });
    return { token, refreshToken, expiryDate, userId: checkUserExist._id };
  }

  async refreshToken(refreshToken: string) {
    const token = await this.refreshTokenModel.findOneAndDelete({
      token: refreshToken,
      expiryDate: { $gte: new Date() },
    });
    if (!token) {
      throw new UnauthorizedException('Expired');
    }
    const newToken = this.jwtService.sign(
      {
        id: token._id,
      },
      {
        expiresIn: '1h',
      },
    );
    const newRefreshToken = uuidv4();
    const expiryDate = new Date();
    expiryDate.setDate(expiryDate.getDate() + 3);

    //store to db
    const addToDb = await this.refreshTokenModel.create({
      token: newRefreshToken,
      userId: token._id,
      expiryDate,
    });
    return { newToken, newRefreshToken, expiryDate };
  }
}
