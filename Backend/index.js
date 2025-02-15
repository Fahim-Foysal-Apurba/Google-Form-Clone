const express= require("express");
const app= express();
const cors= require('cors')
const port = process.env.PORT || 5000;
const getConnection = require('./db');
const db=getConnection();

app.use(express.json());
app.use(cors());

db.connect().then(()=>{
    console.log("Connected")
})

//Add users
app.post("/addUser", async(req, res)=>{

    try{

        const {name, email, password, role}= req.body;
        const q=`Insert into users (name, email, password, role Returning *) Values ($1, $2, $3, $4)`
        await db.query(q, [name, email, password, role], (err, result)=>{

             if(err){
                res.send(err.message)
             }else{
                res.send(result.rows[0])
             }
    
        })

    }catch(err){

        console.error(err.message)

    }
})


//getusers
app.get("/getUsers", async(req, res)=>{
    try{
        const q=`Select * from users`
        await db.query(q, (err, result)=>{
            if(err){
                res.send(err.message)
            }else{
                res.send(result.rows)
            }
        })

    }catch(err){
        console.error(err.message)
    }
})
console.log("hello")

app.listen(port, ()=>{
    console.log("Server is running at http://localhost:"+port)
    console.log("hello")
})