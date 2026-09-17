import express from "express"
import pool from "./data.ts"
import jwt from 'jsonwebtoken'
import dotenv from 'dotenv'
import bcrypt from 'bcryptjs'
dotenv.config()
const app = express()
app.use(express.json())

const PORT = process.env.PORT || 5000

function generateToken (id:number) {
    return jwt.sign({id},process.env.JWT_SECRET!,{
        expiresIn:'30d'
    })
}

app.post('/register',async(req,res)=>{
    try {
        const {name,gmail,number,password,maingoal,track,reminders,airespond} = req.body
        if(!name ||!gmail || !number ||!password||!maingoal||!track||!reminders||!airespond) {
            return res.status(400).json({message:'you didnt fill in expected forms'})
        }
        const hashed = bcrypt.hash(password,10)
        const newUser = await pool.query('INSERT INTO users (name,gmail,number,password,maingoal,track,reminders,airespond) VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',[name,gmail,number,hashed,maingoal,track,reminders,airespond])
        const token = generateToken(newUser.rows[0].id)
        res.json({data:newUser.rows[0],token})
    } catch(err) {
        console.log(err)
        return res.status(500).json({message:"something went wrong"})
    }
})
app.post('/login',async(req,res)=>{
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
            return res.status(404).json({message:'couldnt find user'})
        }
        const isValid = await bcrypt.compare(password,result.rows[0].password)
        if(!isValid) {
            return res.status(403).json({message:'invalid password'})
        }
        const token = generateToken(result.rows[0].id)
        res.json({name:result.rows[0].name,token,id:result.json[0].id})

    } catch(err) {
        console.log(err)
        return res.status(500).json({message:'somethign went wrong'})
    }
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})