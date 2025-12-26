const express = require("express");
const { authenticate } = require("./auth");

const app = express();
app.use(express.json());

// Public route - no authentication required
app.get("/public", (req, res) => {
  res.json({ message: "This is a public endpoint" });
});

// Protected route - authentication required
app.get("/protected", authenticate, (req, res) => {
  res.json({ 
    message: "This is a protected endpoint", 
    user: req.user 
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

module.exports = app;
