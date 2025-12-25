const { Router } = require("express");
const userrouter = Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const axios = require("axios");
const cheerio = require("cheerio");
const User = require("../models/User");
const Preview = require("../models/Preview");

userrouter.post("/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Input validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: "All fields are required" });
    }

    // Username validation
    if (username.length < 3 || username.length > 30) {
      return res.status(400).json({ error: "Username must be between 3 and 30 characters" });
    }
    if (!/^[a-zA-Z0-9_]+$/.test(username)) {
      return res.status(400).json({ error: "Username can only contain letters, numbers, and underscores" });
    }

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({ error: "Invalid email format" });
    }

    // Password validation
    if (password.length < 8) {
      return res.status(400).json({ error: "Password must be at least 8 characters long" });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser)
      return res.status(400).json({ error: "User already exists" });

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate unique API key (timestamp + random)
    const apiKey = Math.random().toString(36).slice(2) + Date.now().toString(36);

    // Create new user
    const newUser = new User({
      username,
      email,
      password: hashedPassword,
      apiKey,
      requestLimit: 50,  // optional default limit
      requestsMade: 0,
      lastRequestAt: new Date(),
    });

    await newUser.save();
    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err); // log the real error
    if (err.code === 11000) {
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});


userrouter.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await User.findOne({ email });
    if (!existingUser) return res.status(401).json({ error: "Invalid credentials" });

    const validPassword = await bcrypt.compare(password, existingUser.password);
    if (!validPassword) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: existingUser._id, email: existingUser.email },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        username: existingUser.username,
        email: existingUser.email,
        apiKey: existingUser.apiKey,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});
//auth middleware to check jwt or api key 
const authmiddleware = async (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  const apikey = req.query.api_key;
  if (token) {
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id); // get full user document
      if (!user) return res.status(401).json({ error: "User not found" });
      req.user = user;
      return next();
    } catch (err) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
  }

  if (apikey) {
    const user = await User.findOne({ apiKey: apikey });
    if (!user) {
      return res.status(401).json({ error: "Invalid API Key" });
    }
    req.user = user;
    return next();
  }

  return res.status(401).json({ error: "No authentication provided" });
}


//http://localhost:3000/api/user/preview?api_key=qup08fu19n example for profile fetching using api key

userrouter.get("/profile", authmiddleware, async (req, res) => {
  try {
    const user = req.user;
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json({
      username: user.username,
      email: user.email,
      apikey: user.apiKey,
      requestMade: user.requestsMade,
      requestLimit: user.requestLimit,
      lastRequestAt: user.lastRequestAt
    });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
});

userrouter.put("/updateprofile", authmiddleware, async (req, res) => {
  try {
    // Whitelist allowed fields to prevent privilege escalation
    const allowedUpdates = {};
    if (req.body.username) allowedUpdates.username = req.body.username;
    if (req.body.email) allowedUpdates.email = req.body.email;

    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      allowedUpdates,
      { new: true, runValidators: true }
    ).select("-password");

    res.json({ message: "Profile updated", updatedUser });
  } catch (err) {
    if (err.code === 11000) {
      return res.status(400).json({ error: "Username or email already exists" });
    }
    res.status(500).json({ error: "Internal server error" });
  }
});

const requestlimitmiddleware = async (req, res, next) => {
  try {
    const user = req.user;
    if (!user) {
      return res.status(401).json({ error: "User not found" });
    }
    const now = new Date();

    // Fix: Proper date calculation for 24-hour reset
    const hoursSinceLastReq = (now - new Date(user.lastRequestAt)) / 3600000;

    if (hoursSinceLastReq >= 24) {
      user.requestsMade = 0;
      user.lastRequestAt = now;
    }

    if (user.requestsMade >= user.requestLimit) {
      return res.status(429).json({ error: "Request limit exceeded. Try again in " + Math.ceil(24 - hoursSinceLastReq) + " hours" });
    }

    // Atomic increment to prevent race conditions
    user.requestsMade++;
    user.lastRequestAt = now;
    await user.save();
    next();

  }
  catch (err) {
    console.error("Rate limit error:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
}

//http://localhost:3000/api/user/previewurl?api_key=qup08fu19n&url=https://my.linkpreview.net/ example for profile fetching using api key

// Helper function to validate URL and prevent SSRF
const isValidUrl = (urlString) => {
  try {
    const url = new URL(urlString);

    // Only allow http and https protocols
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, error: "Only HTTP and HTTPS protocols are allowed" };
    }

    // Block localhost and private IP ranges (SSRF protection)
    const hostname = url.hostname.toLowerCase();
    const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1'];

    if (blockedHosts.includes(hostname)) {
      return { valid: false, error: "Cannot fetch from localhost" };
    }

    // Block private IP ranges
    if (hostname.match(/^10\./) || hostname.match(/^192\.168\./) || hostname.match(/^172\.(1[6-9]|2[0-9]|3[0-1])\./)) {
      return { valid: false, error: "Cannot fetch from private IP addresses" };
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: "Invalid URL format" };
  }
};

userrouter.get("/previewurl", authmiddleware, requestlimitmiddleware, async (req, res) => {
  try {
    const { url } = req.query;
    if (!url) {
      return res.status(400).json({ error: "url is required" });
    }

    // Validate URL and check for SSRF
    const validation = isValidUrl(url);
    if (!validation.valid) {
      return res.status(400).json({ error: validation.error });
    }

    // Fetch with security limits
    const { data } = await axios.get(url, {
      timeout: 5000, // 5 second timeout
      maxContentLength: 1024 * 1024, // 1MB limit
      maxRedirects: 5,
      headers: {
        'User-Agent': 'GlanceBot/1.0 (URL Preview Service)'
      }
    });

    const $ = cheerio.load(data);

    const title = $("title").text().trim() || "No title";
    const description = $('meta[name="description"]').attr("content")?.trim() ||
      $('meta[property="og:description"]').attr("content")?.trim() || "";
    const image = $('meta[property="og:image"]').attr("content") ||
      $('meta[name="twitter:image"]').attr("content") || "";

    // Save preview to DB
    const preview = await Preview.create({
      userId: req.user._id,
      url,
      title,
      description,
      image,
    });

    res.json({
      title: preview.title,
      description: preview.description,
      image: preview.image,
      url: preview.url,
    });

  } catch (err) {
    console.error("Preview fetch error:", err.message);

    if (err.code === 'ECONNABORTED') {
      return res.status(408).json({ error: "Request timeout - URL took too long to respond" });
    }
    if (err.response?.status) {
      return res.status(err.response.status).json({ error: `Failed to fetch URL: ${err.response.statusText}` });
    }

    res.status(500).json({ error: "Could not fetch url data" });
  }
});

userrouter.post("/regenerate-apikey", authmiddleware, async (req, res) => {
  try {
    const newKey = Math.random().toString(36).slice(2) + Date.now().toString(36);
    const updatedUser = await User.findByIdAndUpdate(
      req.user._id,
      { apiKey: newKey },
      { new: true }
    ).select("-password");
    res.json({ message: "API key regenerated successfully", apiKey: newKey });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});
userrouter.get("/stats", authmiddleware, async (req, res) => {
  try {
    const user = req.user;
    res.json({
      username: user.username,
      totalRequests: user.requestsMade,
      remainingRequests: user.requestLimit - user.requestsMade,
      lastRequestAt: user.lastRequestAt,
    });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});


userrouter.get("/history", authmiddleware, async (req, res) => {
  try {
    const previews = await Preview.find({ userId: req.user._id }).sort({ fetchedAt: -1 });
    res.json(previews);
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

userrouter.delete("/delete", authmiddleware, async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user._id);
    await Preview.deleteMany({ userId: req.user._id });
    res.json({ message: "Account deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});


module.exports = userrouter;
