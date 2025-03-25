const express = require('express');
const app = express() ;
const cors = require('cors');

app.use(cors());
app.use(express.json());

const {open} = require('sqlite');
const sqlite3 = require('sqlite3');

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const path = require('path');
const dbPath = path.join(__dirname, 'syncData.db');

const PORT = process.env.PORT || 5000;

let db = null; 
const initializeDBAndServer = async () => {
    try {
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        app.listen(PORT, () => {
            console.log(`Server is running on port ${PORT}`);
        });
    } catch (error) {
        console.error(`DB Error: ${error.message}`);
        process.exit(1);
    }
};

initializeDBAndServer();


//Authentication 
const authenticateToken = (request, response, next) => {
    let jwtToken;
    const authHeader = request.headers["authorization"];
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(" ")[1];
    }
    if (jwtToken === undefined) {
      response.status(401);
      response.send("Invalid JWT Token");
    } else {
      jwt.verify(jwtToken, "TOP", (error, payload) => {
        if (error) {
          response.status(401);
          response.send("Invalid JWT Token");
        } else {
          request.username = payload.username;
          request.userId = payload.userId;
          next();
        }
      });
    }
  };
  

//Register API
app.post("/register/", async (request, response) => {
    try {
        const {username, password, email } = request.body;
        const selectUserQuery = `
          SELECT * 
          FROM users
          WHERE username = ?;
        `;
        const dbUser = await db.get(selectUserQuery, [username]);

        if (dbUser === undefined) {
            if (password.length < 3) {
                response.status(400).send("Password is too short");
            } else {
                const hashedPassword = await bcrypt.hash(password, 10);
                const createUserQuery = `
                  INSERT INTO 
                      users (username, password, email)
                  VALUES 
                      (?, ?, ?);
                `;
                await db.run(createUserQuery, [username, hashedPassword, email]);
                response.send("User created successfully");
            }
        } else {
            response.status(400).send("User already exists");
        }
    } catch (error) {
        console.error(error);
        response.status(500).send("Internal server error");
    }
});


//Login API  
app.post("/login/", async (request, response) => {
    const { username, password } = request.body;
    const selectUserQuery = `
      SELECT * 
      FROM users 
      WHERE username = ?;
    `;
  
    try {
      const dbUser = await db.get(selectUserQuery, [username]);
      if (dbUser === undefined) {
        response.status(400).send("Invalid user");
        return;
      }
  
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
      if (isPasswordMatched) {
        const payload = { username: dbUser.name, userId: dbUser.id };
        const jwtToken = jwt.sign(payload, "TOP"); 
        response.send({ jwtToken });
      } else {
        response.status(400).send("Invalid password");
      }
    } catch (error) {
      console.error("Error during login:", error);
      response.status(500).send("Internal server error");
    }
});



app.get('/dashboard', authenticateToken, async (req, res) => {
    try {
      const statesQuery = 'SELECT * FROM states'; 
      const states = await db.all(statesQuery); 
  
      res.json(states);
    } catch (error) {
      console.error('Error fetching states:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  });
app.get('/api/map', authenticateToken, (req, res) => {
  res.json({ center: [20.5937, 78.9629], zoom: 5 });
});

