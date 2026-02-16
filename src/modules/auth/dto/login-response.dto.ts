import { ApiProperty } from "@nestjs/swagger";


export class LoginResponseDto {
  @ApiProperty()
  accessToken: string;

  @ApiProperty()
  refreshToken: string;

  @ApiProperty()
  user: {
    id: string;
    fullName: string;
    phoneNumber: string;
    role: string;
    isVerified: boolean;
  };
}
