const express = require('express');
const app = express();
require('dotenv').config();
const cors = require('cors');   
// just requiring will run the mongoose.connect() inside db.js
require('./db');  

const userrouter = require('./routes/userauth');
const adminrouter = require('./routes/admin');
app.use(
  cors({
    origin: "http://localhost:5173", // frontend origin
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true, // if you need cookies/auth headers
  })
);
app.use(express.json());
app.use('/api/user', userrouter);
app.use('/api/admin', adminrouter);

app.get('/api/health', (req, res) => {
    res.status(200).json({
        status: 'ok',
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        message: 'Server is healthy'
    });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`server is running on port ${PORT}`);
});
