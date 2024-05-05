import express from "express";
import bodyParser from "body-parser";
import cors from "cors";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";

const app = express();
const port = 3001;

// Middleware
app.use(cors());
app.use(bodyParser.json());

//connect to DB
const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: "root",
  database: "bank",
  port: 3306,
});

// Generera engångslösenord
function generateOTP() {
  // Generera en sexsiffrig numerisk OTP
  const otp = Math.floor(100000 + Math.random() * 900000);
  return otp.toString();
}

// Din kod här. Skriv dina arrayer
const users = [];
const accounts = [];
const sessions = [];

//help function to make code look nicer
async function query(sql, params) {
  const [results] = await pool.execute(sql, params);
  return results;
}

// Skapa användare endpoint
app.post("/users", async (req, res) => {
  const { username, password } = req.body;

  //kryptera lösenordet innan det hamnar i DB
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  console.log("hashedPassword", hashedPassword);

  try {
    // Execute the SQL query and wait for the result
    const result = await query(
      "INSERT INTO users (username, password) VALUES (?, ?)",
      [username, hashedPassword]
    );

    const id = result.insertId; // Get the ID of the inserted user
    const newUser = { id, username, password };
    users.push(newUser);

    console.log(newUser);

    // Skapa ett konto med 0 kr som saldo för den nya användaren
    const accountId = accounts.length + 1;
    const newAccount = { id: accountId, userId: id, amount: 0 };
    accounts.push(newAccount);

    console.log(newAccount);

    res.status(201).json({
      success: true,
      message: "Användare och konto skapade framgångsrikt.",
    });
  } catch (error) {
    console.error("error creating user:", error);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// Logga in endpoint
app.post("/sessions", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Query the database to find the user by username
    const result = await query("SELECT * FROM users WHERE username = ?", [
      username,
    ]);

    // If no user found, return 401 Unauthorized
    if (result.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Ogiltiga inloggningsuppgifter." });
    }

    // Extract user from query result
    const user = result[0];

    // Compare passwords asynchronously
    const passwordMatch = await bcrypt.compare(password, user.password);

    // If passwords don't match, return 401 Unauthorized
    if (!passwordMatch) {
      return res
        .status(401)
        .json({ success: false, message: "Ogiltiga inloggningsuppgifter." });
    }

    // Passwords match, generate token and save session
    const token = generateOTP();
    sessions.push({ userId: user.id, token });

    // Return success response with token
    res.json({ success: true, token });

    console.log(sessions);
  } catch (error) {
    // Handle any errors that might occur
    console.error("Error during login:", error);
    res.status(500).json({
      success: false,
      message: "Ett fel inträffade under inloggningen.",
    });
  }
});

//update password
app.put("/new-password", async (req, res) => {
  const { username, oldPassword, newPassword } = req.body;

  const result = await query("SELECT * FROM users WHERE username = ?", [
    username,
  ]);
  const user = result[0];

  const passwordMatch = await bcrypt.compare(oldPassword, user.password);

  if (!passwordMatch) {
    return res.status(401).json({ success: false, message: "Ogiltigt" });
  }

  const saltRounds = 10;
  const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

  try {
    const updateResult = await query(
      "UPDATE users SET password = ? WHERE id = ?",
      [hashedNewPassword, user.id]
    );
    res.status(204).send("User updated");
  } catch (error) {
    res.status(500).send("Error updating user");
  }
});

//delete user
app.delete("/users", async (req, res) => {
  const { username } = req.body;

  try {
    const deleteResult = await query("DELETE FROM users WHERE username = ?", [
      username,
    ]);
    console.log("deleteResult", deleteResult);
    res.send("user deleted");
  } catch (error) {
    res.status(500).send("Error deleting user");
  }
});

// Visa saldo endpoint
app.post("/me/accounts", (req, res) => {
  const { token } = req.body;

  console.log("token", token); //vi hämtar inte token därför får vi null

  const session = sessions.find((session) => session.token === token);

  if (!session) {
    return res
      .status(401)
      .json({ success: false, message: "Ogiltig sessions token." });
  }

  const userId = session.userId;
  const account = accounts.find((account) => account.userId === userId);

  if (!account) {
    return res
      .status(404)
      .json({ success: false, message: "Konto hittades inte för användaren." });
  }

  res.json({ success: true, amount: account.amount });
  console.log(account);
});

// Sätt in pengar endpoint
app.post("/me/accounts/transactions", (req, res) => {
  const { token, amount, otp } = req.body;

  const session = sessions.find((session) => session.token === token);

  if (!session) {
    return res
      .status(401)
      .json({ success: false, message: "Ogiltig sessions token." });
  }

  const userId = session.userId;
  const user = users.find((user) => user.id === userId);

  if (!user) {
    return res
      .status(401)
      .json({ success: false, message: "Ogiltiga autentiseringsuppgifter." });
  }

  const account = accounts.find((account) => account.userId === userId);

  if (!account) {
    return res
      .status(404)
      .json({ success: false, message: "Konto hittades inte för användaren." });
  }

  // Kontrollera om det angivna engångslösenordet matchar det sparade för användaren
  const sessionWithOTP = sessions.find(
    (session) => session.token === token && session.otp === otp
  );

  if (!sessionWithOTP) {
    return res
      .status(401)
      .json({ success: false, message: "Felaktigt engångslösenord." });
  }

  // Lägg till det insatta beloppet till saldot
  account.amount += parseFloat(amount);

  res.json({ success: true, newBalance: account.amount });
});

// Starta servern
app.listen(port, () => {
  console.log(`Bankens backend körs på port:${port}`);
});
