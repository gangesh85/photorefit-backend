import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import { pool } from "../db.js";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const host = process.env.HOST;
const port = process.env.PORT;
const jwtKey = process.env.JWT_SECRET;

app.use(cors());
app.use(express.json());

app.get("/users", verifyToken, async (req, res) => {
  try {
    let result = await pool.query(`SELECT * FROM  users`);
    res.send(result.rows);
  } catch (err) {
    res.status(500).send(`Internal server error!`);
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (email && password) {
    try {
      const result = await pool.query(
        `SELECT id, name, email  FROM users WHERE email = $1 AND password = $2`,
        [email, password]
      );
      const user = result.rows[0];
      if (user && password) {
        jwt.sign({ user }, jwtKey, { expiresIn: "1h" }, (err, token) => {
          res.send({ user, auth: token });
        });
      } else {
        res.send({ result: "User not found!" });
      }
    } catch (err) {
      res.status(500).send({ error: "Login failed", details: err.message });
    }
  } else {
    res.send({ result: "User not found!" });
  }
});

function verifyToken(req, res, next) {
  let token = req.headers["authorization"];
  if (token) {
    jwt.verify(token, jwtKey, (err, decoded) => {
      if (err) {
        return res.status(403).send({ response: "Invalid Access" });
      }
      req.user = decoded.user;
      next();
    });
  } else {
    res.status(401).send({ response: "Access denied" });
  }
}

app.listen(port, () => {
  console.log(`server is running on port http://${host}:${port}`);
});
