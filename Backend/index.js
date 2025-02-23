const express = require('express');
const app = express();
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const pool = require('./db'); // Import single DB connection pool
const cors = require('cors');
const port = 5000;

// Middleware
app.use(express.json());
app.use(cors({
    origin: 'https://ffa-form.netlify.app',  
    credentials: true  
}));

app.use(bodyParser.json());

// Setup session with in-memory store 
app.use(
    session({
        secret: 'foysal',
        resave: false,
        saveUninitialized: false, 
        cookie: { secure: false, httpOnly: true, maxAge: 24 * 60 * 60 * 1000 } // 1-day expiry
    })
);

// Register User
app.post('/addUser', async (req, res) => {
    try {
        const { user_name, email, password } = req.body;

        const ecq = 'SELECT * FROM users WHERE email = $1';
        const ecr = await pool.query(ecq, [email]);

        if (ecr.rows.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const iq = 'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *';
        const iqr = await pool.query(iq, [user_name, email, hashedPassword]);

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

// Login
app.post('/login', async (req, res) => {
    try {
        const { email1, password1 } = req.body;
        const q = "SELECT * FROM users WHERE email = $1";
        const qr = await pool.query(q, [email1]);

        if (qr.rows.length === 0 || qr.rows[0].deleted_at !== null) {
            return res.status(404).json({ message: "This email is not registered!" });
        }

        const isPasswordCorrect = await bcrypt.compare(password1, qr.rows[0].password);
        if (!isPasswordCorrect) {
            return res.status(401).json({ message: "Wrong Password" });
        }

        if (qr.rows[0].block_status === true) {
            return res.status(403).json({ message: "Your account is blocked!" });
        }

        // Create session
        req.session.user = {
            id: qr.rows[0].id,
            name: qr.rows[0].name,
            email: qr.rows[0].email,
            mode: qr.rows[0].mode,
            role: qr.rows[0].role
        };

        return res.status(200).json({ message: "Login Successful", user: req.session.user });

    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Logout
app.post('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ message: 'Logout failed' });
        }
        res.clearCookie('connect.sid'); // Clear session cookie
        return res.status(200).json({ message: 'Logged out successfully' });
    });
});

// Get Users
app.get("/getUsers", async (req, res) => {
    try {
        const q = "SELECT * FROM users WHERE deleted_at IS NULL";
        const result = await pool.query(q);
        res.json(result.rows);
    } catch (err) {
        console.error("Error fetching users:", err);
        res.status(500).json({ message: "Server error" });
    }
});

// Get user info
app.get("/getUserInfo/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const q = "SELECT * FROM users WHERE id = $1";
        const result = await pool.query(q, [id]);

        return res.json(result.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// Update a user's details
app.put('/update/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { data } = req.body;
        const q = "UPDATE users SET name = $1 WHERE id = $2 RETURNING *";
        const result = await pool.query(q, [data, id]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// Block User
app.put('/block/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const q = "UPDATE users SET block_status = true WHERE id = $1 RETURNING *";
        const result = await pool.query(q, [id]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// Unblock User
app.put('/unblock/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const q = "UPDATE users SET block_status = false WHERE id = $1 RETURNING *";
        const result = await pool.query(q, [id]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// Promote to Admin
app.put('/addAdmin/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const q = "UPDATE users SET role = 'admin' WHERE id = $1 RETURNING *";
        const result = await pool.query(q, [id]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// remove admin
app.put('/removeAdmin/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const q = "UPDATE users SET role= 'user' WHERE id = $1 RETURNING *";
        const result = await pool.query(q, [id]);
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});
// Update mode to Light
app.put('/updateModeLight/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log("Received request to update light mode for ID:", id);

        const q = "UPDATE users SET mode = false WHERE id = $1 RETURNING *"; 
        const result = await pool.query(q, [id]);

        console.log("Update result:", result.rows);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error("Error in updateModeLight:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});

// Update mode to Dark
app.put('/updateModeDark/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log("Received request to update dark mode for ID:", id);

        const q = "UPDATE users SET mode = true WHERE id = $1 RETURNING *"; 
        const result = await pool.query(q, [id]);

        console.log("Update result:", result.rows);

        if (result.rows.length === 0) {
            return res.status(404).json({ message: "User not found" });
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error("Error in updateModeDark:", err.message);
        res.status(500).json({ message: "Server error" });
    }
});



// Soft Delete User
app.delete("/delete/:id", async (req, res) => {
    try {
        const { id } = req.params;
        const q = "UPDATE users SET deleted_at = NOW() WHERE id = $1 RETURNING *";
        const result = await pool.query(q, [id]);
        res.json({ message: "User deleted!", user: result.rows[0] });
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});
app.post('/getUsers/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const q = "SELECT * FROM users WHERE id = $1";
        const result = await pool.query(q, [id]);
        res.json(result.rows);
    } catch (err) {
        console.error(err.message);
        res.status(500).json({ message: "Server error" });
    }
});




////////////////////

///form apis
// Create a new form with questions
app.post("/forms", async (req, res) => {
    try {
      const { title, questions, id } = req.body;
  
      // Insert the form
      const formResult = await pool.query(
        "INSERT INTO forms (user_id, title) VALUES ($1, $2) RETURNING id",
        [id, title]
      );
      const formId = formResult.rows[0].id;
  
      // Insert questions
      const questionQueries = questions.map((q) =>
        pool.query(
          "INSERT INTO questions (form_id, question_data) VALUES ($1, $2)",
          [formId, q]
        )
      );
      await Promise.all(questionQueries);
  
      res.status(201).json({ message: "Form created successfully!", formId });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  });
  
  // Get all forms
  app.get("/getforms", async (req, res) => {
    try {
      const result = await pool.query("SELECT * FROM forms");
      res.json(result.rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Server error" });
    }
  });
  
  // Get a single form with questions
  app.get("/forms/:id", async (req, res) => {
    try {
      const form_Id = parseInt(req.params.id); // Convert ID to an integer
  
      if (isNaN(form_Id)) {
        return res.status(400).json({ error: "Invalid form ID" });
      }
  
      // Get form details
      const formResult = await pool.query("SELECT * FROM forms WHERE id = $1", [
        form_Id,
      ]);
  
      if (formResult.rows.length === 0) {
        return res.status(404).json({ error: "Form not found" });
      }
  
      // Get questions related to the form
      const questionsResult = await pool.query(
        "SELECT id, question_data FROM questions WHERE form_id = $1",
        [form_Id]
      );
  
      res.json({
        form: formResult.rows[0],
        questions: questionsResult.rows.map((q) => ({
          id: q.id,
          ...q.question_data, // Assuming question_data is stored as JSONB
        })),
      });
    } catch (err) {
      console.error("Error fetching form:", err);
      res.status(500).json({ error: "Server error" });
    }
  });


  
  app.post("/answers", async (req, res) => {
    try {
      const { form_id, answers } = req.body; // answers = [{ questionId, answer }]
      
      if (!Array.isArray(answers) || !answers.length) {
        return res.status(400).json({ error: "No answers provided" });
      }
  
      // Ensure answers are properly formatted as JSONB
      const query = "INSERT INTO answers (form_id, question_id, answer_data) VALUES ($1, $2, $3)";
      for (const ans of answers) {
        const { questionId, answer } = ans;
  
        if (!questionId || typeof answer === 'undefined' || answer === null) {
          continue; // Skip invalid answers
        }
        const answerJson = JSON.stringify(answer); 
        await pool.query(query, [form_id, questionId, answerJson]);
      }
  
      res.status(201).json({ message: "Answers submitted successfully" });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Error submitting answers" });
    }
  });
  
  
  
  


app.listen(port, () => {
    console.log("Server is running on https://google-form-clone-wck5.onrender.com");
});


