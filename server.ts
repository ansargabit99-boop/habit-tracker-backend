import express from "express"
import pool from "./data.ts"
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
import rateLimit from 'express-rate-limit'
import type { Request,Response,NextFunction } from "express"
import cors from 'cors'
dotenv.config()
const app = express()
app.use(express.json({limit:'10kb'}))
app.set('trust proxy', 1)
app.use(cors())

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
async function reCalculateStreak(habit_id:number) {
    const result = await pool.query('SELECT completed_at FROM habit_completions WHERE habit_id=$1 ORDER by completed_at DESC',[habit_id])
    const dates = result.rows.map(r=>new Date(r.completed_at).toDateString())
    const dataSet = new Set(dates)
    let streak = 0
    let cursor = new Date()

    if(!dataSet.has(cursor.toDateString())){
        cursor.setDate(cursor.getDate() - 1)
    }
    while(dataSet.has(cursor.toDateString())) {
        streak++
        cursor.setDate(cursor.getDate()-1)
    }
    return streak
}
app.post('/habits/:id/complete',middleware,async(req:any,res)=>{
    try {
        const id = req.params.id
        const user_id = req.user
        const habitCheck = await pool.query('SELECT * FROM habits WHERE id=$1 AND user_id=$1',[id,user_id])
        if(habitCheck.rows.length){
            return res.status(404).json({message:'habit not found'})
        }
        const already = await pool.query('SELECT * FROM habit_completions WHERE habit_id=$1 AND completed_at=CURRENT_DATE',[id])
        if(already.rows.length > 0){
            return res.status(400).json({message:'already completed today'})
        }
        await pool.query('INSERT INTO habit_completions (habit_id,completed_at) VALUES ($1,CURRENT_DATE)',[id])
        const newStreak = await reCalculateStreak(Number(id))
        const update = await pool.query('UPDATE habits SET streak=$1 WHERE id=$2',[newStreak,id])
        res.json(update.rows[0])
    } catch(err) {
        console.log(err)
    }
})
app.delete('/habits/:id/complete',async(req,res)=>{
    try {
        const id =req.params.id
        await pool.query('DELETE FROM habit_completions WHERE habit_id =$1 AND completed_at=CURRENT_DATE',[id])
        const newStreak = await reCalculateStreak(Number(id))
        const updated = await pool.query('UPDATE habits SET streak=$1 WHERE id=$2 RETURNING * ',[newStreak,id])
        res.json(updated.rows[0])
    } catch(err) {
        console.log(err)
    }
})
app.get('/me',middleware,async(req:any,res)=>{
    try {
        const user_id = req.user
        const me = await pool.query('SELECT id,name,gmail,number FROM users WHERE user_id=$1',[user_id])
        res.json(me.rows[0])
    } catch(err) {
        console.log(err)
    }
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})