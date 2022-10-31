import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import { PrismaClient } from "@prisma/client"

const prisma = new PrismaClient();

export const create = async ctx => {
    //criptografando senha
    const password = await bcrypt.hash(ctx.request.body.password, 10)

    const data = {
        name: ctx.request.body.name,
        username: ctx.request.body.username,
        email: ctx.request.body.email,
        password,
    }

    try {
        const { password, ...user } = await prisma.user.create({ data });
        ctx.body = user;
        ctx.status = 201;
    } catch (e) {
        ctx.body = e;
        ctx.status = 500;
    }
}

export const login = async ctx => {
    const [type, token] = ctx.headers.authorization.split(" ")
    const [email, plainTPassword] = atob(token).split(":")
    
    const user = await prisma.user.findUnique({
        where: { email }
    })

    if (!user) {
        ctx.status = 404
        return;
    }

    const passwordMatch = await bcrypt.compare(plainTPassword, user.password)

    if (!passwordMatch) {
        ctx.status = 404
        return;
    }

    const { password, ...result } = user

    const accessToken = jwt.sign({
        sub: user.id,
        name: user.name,
        expiresIn: "7d"
    }, process.env.JWT_SECRET)

    ctx.body = {
        user: result,
        accessToken
    }
}



export const userHunches = async ctx => {
    const username = ctx.request.params.username
    const user = await prisma.user.findUnique({
        where: {
            username
        }
    })

    if (!user) {
        ctx.status = 404
        return;
    }

    const hunches = await prisma.hunch.findMany({
        where: {
            userId: user.id
        }
    });

    ctx.body = {
        name: user.name,
        hunches,
    }
}    