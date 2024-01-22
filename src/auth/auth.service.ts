import { Injectable, ForbiddenException } from "@nestjs/common";
import { User, Bookmark } from "@prisma/client";
// import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon from 'argon2'
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";
@Injectable()
export class AuthService {
    constructor(private prsima: PrismaService, private jwt: JwtService, private config: ConfigService) { }
    async signUp(dto: AuthDto) {
        const hashpassword: string = await argon.hash(dto.password)
        try {
            const user = await this.prsima.user.create({
                data: {
                    email: dto.email,
                    hash: hashpassword
                },
            })
            return user

        } catch (error) {
            {

                throw new ForbiddenException(
                    'Credentials taken',
                );


            }
        }
    }


    async signin(dto: AuthDto) {
        // find the user by email
        const user =
            await this.prsima.user.findUnique({
                where: {
                    email: dto.email,
                },
            });
        // if user does not exist throw exception
        if (!user)
            throw new ForbiddenException(
                'Credentials incorrect',
            );

        // compare password
        const pwMatches = await argon.verify(
            user.hash,
            dto.password,
        );
        // if password incorrect throw exception
        if (!pwMatches)
            throw new ForbiddenException(
                'Credentials incorrect',
            );
        return this.signToken(user.id, user.email)
    }

    async signToken(
        userId: number,
        email: string,
    ): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email,
        };
        const secret = this.config.get('JWT_SECRET');
        console.log({ secret })

        const token = await this.jwt.signAsync(
            payload,
            {
                expiresIn: '15m',
                secret: secret,
            },
        );

        return {
            access_token: token,
        };
    }

}


