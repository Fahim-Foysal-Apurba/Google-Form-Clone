const express=require('express');
const app=express();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const getConnection=require('./db');
const con= getConnection();
const cors= require('cors');
const port=5000;

//middleware
app.use(express.json());
app.use(cors());

con.connect().then(()=>{
    console.log("Connected Foysal")
})

//ROUTES
//create a TODO
app.use(bodyParser.json());
app.use(
    session({
        secret: 'your_secret_key',
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false } // Use `true` if using HTTPS
    })
);

// Register 
app.post('/addUser', async (req, res) => {
    try {
        const { user_name, email, password } = req.body;

        // Check if the email already exists
        const ecq = 'SELECT * FROM users WHERE email = $1';
        const ecr = await con.query(ecq, [email]);

        if (ecr.rows.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Encrypt the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const iq = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *';
        const iqr = await con.query(iq, [user_name, email, hashedPassword]);

        // Create session
        req.session.user = {
            id: iqr.rows[0].id,
            name: iqr.rows[0].name,
            email: iqr.rows[0].email,
            mode: iqr.rows[0].mode,
            role: iqr.rows[0].role
        };

        res.status(201).json({ message: 'User registered successfully', user: req.session.user });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: 'Server error' });
    }
});


//Login
app.post('/login', async(req, res)=>{
    try{

        const {email1, password1}= req.body;
        const q="Select * from users where email=($1)"

        const qr=await con.query(q, [email1]);

        if(qr.rows.length === 0 || qr.rows[0].deleted_at !== null){

           return res.status(404).json({message: "This email is not registered!"})           
        } 
        if (await bcrypt.compare(password1, qr.rows[0].password)===false){
            return res.status(404).json({message: "Wrong Password", user: req.session.user});
        } 
        if(qr.rows[0].block_status===true){
            return res.status(404).json({message: "Your account is blocked!"});
        }
        
        // create session 

        req.session.user ={
            id: qr.rows[0].id,
            name: qr.rows[0].name,
            email: qr.rows[0].email,
            mode: qr.rows[0].mode,
            role: qr.rows[0].role,
            deleted_at: qr.rows[0].deleted_at

        };
        if(qr.rows[0].deleted_at === null){
            return res.status(403).json({message: "Login Successfully", user: req.session.user});}
          

    }catch(err){
        res.status(500).json({message: "server error"})
    }
})


app.get("/getUsers", async (req, res)=>{
    try{
        const q="Select * from users"
        await con.query(q, (err, result)=>{
            if(err){
                res.send(err.message)
            }else{
                console.log(result.rows)
                res.send(result.rows)
            }
        })

    }catch(err){
        res.send(err.message)
    }
})

//get a todo

app.get("/getaData/:id", async (req, res)=>{

    try{
        const{ id }= req.params;
        const q="Select * from todo where id=($1)"
        await con.query(q, [id], (err, result)=>{
            if(err){
                res.send(err.message)
            }else{
                console.log(result.rows)
                res.send(result.rows)
            }
        })

    }catch(err){
        res.send(err.message)
    }
})

//update a todo 
//app.use(express.json()); // Ensure JSON parsing middleware is in place
app.put('/update/:id', async(req, res)=>{

    try{
    const { id }= req.params;
    const { data } = req.body;
    const q = "UPDATE todo SET description = $1 WHERE id = $2 RETURNING *";
    await con.query(q, [data, id], (err, result)=>{
        if(err){
            res.send(err.message)
        }else{
            console.log(result.rows[0]);
            res.send(result.rows[0]);
        }
    })


    }catch(err){
        console.log(err.message)
    }
    
})

//delete a todo

app.delete("/delete/:id", async(req, res)=>{
    const {id}= req.params;
    const q = "Delete from todo WHERE id= $1"

    await con.query(q, [id], (err, result)=>{
        if(err){
            res.send(err.message)
        }else{
            res.send("Deleted!")
        }
    })

})

app.listen(port, ()=> {
    console.log("server is running in http://localhost:"+ port);
})