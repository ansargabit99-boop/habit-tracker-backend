import express from "express"
import pool from "./data.ts"
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import rateLimit from 'express-rate-limit'
import type { Request,Response,NextFunction } from "express"
dotenv.config()
const app = express()
app.use(express.json({limit:'10kb'}))
app.set('trust proxy', 1)

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET is not set')
}

const PORT = process.env.PORT || 5000
const LoginLimitter = rateLimit({windowMs:15*60*1000,max:10})

function generateToken (id:number) {
    return jwt.sign({id},process.env.JWT_SECRET!,{
        expiresIn:'30d'
    })
}
function middleware(req:any,res:Response,next:NextFunction) {
    const auth = req.headers.authorization
    if(!auth) {
        return res.status(403).json({message:'unauthorised'})
    } 
    const token = auth.split(' ')[1]
    if(!token) {
        return res.status(403).json({message:"something went wrong"})
    }
    try {
    const decoded = jwt.verify(token,process.env.JWT_SECRET!) as {id:number}
    req.user = decoded.id
    next() 
    } catch(err) {
        console.log(err)
        return res.json({message:'invalid or expired token'})
    }
}

app.post('/register',async(req,res)=>{
    try {
        const {name,gmail,number,password,maingoal,track,reminders,airespond} = req.body
        if (password.length < 7) {
            return res.status(400).json({message:'the password should contain atLeast 8 characters'})
        }
        if(!name ||!gmail || !number ||!password||!maingoal||!track||!reminders||!airespond) {
            return res.status(400).json({message:'you didnt fill in expected forms'})
        }
        const hashed =await bcrypt.hash(password,10)
        const newUser = await pool.query('INSERT INTO users (name,gmail,number,password,maingoal,track,reminders,airespond) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[name,gmail,number,hashed,maingoal,track,reminders,airespond])
        const token = generateToken(newUser.rows[0].id)
        const { password: _, ...safeUser } = newUser.rows[0]
        res.json({ data: safeUser, token })
    } catch(err) {
        console.log(err)
        return res.status(500).json({message:"something went wrong"})
    }
})
app.post('/login',LoginLimitter,async(req,res)=>{
    try {
        const {gmailOrNum,password} = req.body
        let result:any
        if(password.length <7) {
            return res.status(400).json({message:"password length should be at least 8 characters"})
        }
        if(gmailOrNum.includes('@') || gmailOrNum.includes(".")){
            result = await pool.query('SELECT * FROM users WHERE gmail= $1',[gmailOrNum])
        } else {
            result = await pool.query('SELECT * FROM users WHERE number=$1',[gmailOrNum])
        }
        if(result.rows.length ===0) {
            return res.status(401).json({message:'invalid credentials'})
        }
        const isValid = await bcrypt.compare(password,result.rows[0].password)
        if(!isValid) {
            return res.status(401).json({message:'invalid credential'})
        }
        const token = generateToken(result.rows[0].id)
        res.json({name:result.rows[0].name,token,id:result.rows[0].id})

    } catch(err) {
        console.log(err)
        return res.status(500).json({message:'somethign went wrong'})
    }
})
app.get('/habits',middleware,async(req:any,res)=>{
    const user_id = req.user
    try {
        const habits = await pool.query('SELECT * FROM habits WHERE user_id=$1',[user_id])
        res.json(habits.rows)
    } catch(err) {
        console.log(err)
        return res.status(500).json({message:'something went wrong '})
    }
})
app.post('/habits',middleware,async(req:any,res)=>{
    try {
        const {habit} =req.body
        const user_id = req.user
        const newHabit = await pool.query('INSERT INTO habits (habit,user_id) VALUES ($1,$2) RETURNING *',[habit,user_id])
        res.json(newHabit.rows[0])
    } catch(err) {
        console.log(err)
        res.status(500).json({message:'something went wrong'})
    }
})
app.delete('/habits/:id',middleware,async(req,res)=>{
    try {
        const id = req.params.id
        await pool.query('DELETE FROM habits WHERE id=$1 RETURNING*',[id])
        res.json({message:'message succesfully deleted'})
    } catch(err) {
        console.log(err) 
        return res.status(500).json({message:'something went wrong'})
    }
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})