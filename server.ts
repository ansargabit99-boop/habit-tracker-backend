import express from "express"

const app = express()

const PORT = process.env.PORT || 5000

app.get("/", (req, res) => {
    res.send("Habit Tracker API is running!")
})

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`)
})