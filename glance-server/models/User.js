
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  password: {
    type: String,
    required: true,
  },
  apiKey: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  requestsMade: {
    type: Number,
    default: 0,
  },
  requestLimit: {
    type: Number,
    default: 100,
  },
  lastRequestAt: {
    type: Date,
    default: Date.now
  },
  createdAt: {
    type: Date,
    default: Date.now,
  },
});

module.exports = mongoose.model("User", userSchema);
