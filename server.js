// ===============================
// IMPORTS
// ===============================
const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

console.log("File started...");

// ===============================
// APP SETUP
// ===============================
const app = express();
app.use(express.json());

// ===============================
// IN-MEMORY STORAGE
// ===============================
let users = [];
let events = [];

// ===============================
// AUTH MIDDLEWARE
// ===============================
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access denied. No token." });
  }

  jwt.verify(token, "secretkey123", (err, user) => {
    if (err) {
      return res.status(403).json({ message: "Invalid token" });
    }

    req.user = user;
    next();
  });
}

// ===============================
// HOME ROUTE
// ===============================
app.get("/", (req, res) => {
  res.send("Backend Running 🚀");
});

// ===============================
// REGISTER ROUTE
// ===============================
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const userExists = users.find(user => user.email === email);
  if (userExists) {
    return res.status(400).json({ message: "User already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    name,
    email,
    password: hashedPassword
  };

  users.push(newUser);

  res.status(201).json({ message: "User registered successfully" });
});

// ===============================
// LOGIN ROUTE
// ===============================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);
  if (!user) {
    return res.status(400).json({ message: "User not found" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid password" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    "secretkey123",
    { expiresIn: "1h" }
  );

  res.json({
    message: "Login successful",
    token
  });
});

// ===============================
// PROTECTED PROFILE ROUTE
// ===============================
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    message: "Protected route accessed",
    user: req.user
  });
});

// ===============================
// CREATE EVENT (PROTECTED)
// ===============================
app.post("/events", authenticateToken, (req, res) => {
  const { title, description, date } = req.body;

  const newEvent = {
    id: events.length + 1,
    title,
    description,
    date,
    createdBy: req.user.id,
    participants: []
  };

  events.push(newEvent);

  res.status(201).json({
    message: "Event created successfully",
    event: newEvent
  });
});

// ===============================
// GET ALL EVENTS
// ===============================
app.get("/events", (req, res) => {
  res.json(events);
});

// ===============================
// JOIN EVENT (PROTECTED)
// ===============================
app.post("/events/:id/join", authenticateToken, (req, res) => {
  const eventId = parseInt(req.params.id);

  const event = events.find(e => e.id === eventId);

  if (!event) {
    return res.status(404).json({ message: "Event not found" });
  }

  const alreadyJoined = event.participants.includes(req.user.id);

  if (alreadyJoined) {
    return res.status(400).json({ message: "Already joined this event" });
  }

  event.participants.push(req.user.id);

  res.json({
    message: "Successfully joined event",
    event
  });
});

// ===============================
// GET SINGLE EVENT
// ===============================

app.get("/events/:id", (req, res) => {
  const eventId = parseInt(req.params.id);
  const event = events.find(e => e.id === eventId);

  if (!event) {
    return res.status(404).json({ message: "Event not found" });
  }

  res.json(event);
});

// ===============================
// UPDATE EVENT (PROTECTED)
// ===============================

app.put("/events/:id", authenticateToken, (req, res) => {
  const eventId = parseInt(req.params.id);
  const event = events.find(e => e.id === eventId);

  if (!event) {
    return res.status(404).json({ message: "Event not found" });
  }

  // Only creator can update
  if (event.createdBy !== req.user.id) {
    return res.status(403).json({ message: "Not authorized to update this event" });
  }

  const { title, description, date } = req.body;

  if (title) event.title = title;
  if (description) event.description = description;
  if (date) event.date = date;

  res.json({
    message: "Event updated successfully",
    event
  });
});

// ===============================
// DELETE EVENT (PROTECTED)
// ===============================

app.delete("/events/:id", authenticateToken, (req, res) => {
  const eventId = parseInt(req.params.id);
  const eventIndex = events.findIndex(e => e.id === eventId);

  if (eventIndex === -1) {
    return res.status(404).json({ message: "Event not found" });
  }

  const event = events[eventIndex];

  // Only creator can delete
  if (event.createdBy !== req.user.id) {
    return res.status(403).json({ message: "Not authorized to delete this event" });
  }

  events.splice(eventIndex, 1);

  res.json({ message: "Event deleted successfully" });
});


// ===============================
// SERVER LISTEN
// ===============================
app.listen(3000, () => {
  console.log("Server started on port 3000");
});