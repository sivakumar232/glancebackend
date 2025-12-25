const mongoose = require("mongoose");

const previewSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User", index: true },
  url: String,
  title: String,
  description: String,
  image: String,
  fetchedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Preview", previewSchema);
