import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { AppService } from './app.service';
import { AuthGuard } from './guard/auth.guard';
import { AdminGuard } from './guard/admin.guard';
import { Roles } from './auth/decorators/roles.decorator';

@Controller()
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get()
  @Roles(['admin'])
  @UseGuards(AdminGuard)
  getHello(@Req() req) {
    console.log(req.userId);
    return {
      message: 'Hello World!!',
      userId: req.userId,
    };
  }

  @Get('hello')
  getHelloWithoutGuard() {
    return 'Hello World!';
  }
}
