
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

mongoose.connect(process.env.MONGO_URI)
.then(()=> console.log("MongoDB Connected"))
.catch(err=> console.log(err));

const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  premium: { type: Boolean, default: false }
});

const User = mongoose.model("User", userSchema);

// Register
app.post("/register", async (req,res)=>{
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password,10);
  await User.create({ username, password: hashed });
  res.json({ message: "Registered" });
});

// Login
app.post("/login", async (req,res)=>{
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if(!user) return res.status(400).json({ message:"User not found"});
  const valid = await bcrypt.compare(password, user.password);
  if(!valid) return res.status(400).json({ message:"Invalid password"});
  const token = jwt.sign({ id:user._id }, process.env.JWT_SECRET);
  res.json({ token, premium:user.premium });
});

// OPay Verification (REAL API STRUCTURE)
app.post("/verify-payment", async (req,res)=>{
  const { reference, userId } = req.body;

  try{
    const response = await axios.post(
      "https://api.opaycheckout.com/api/v1/international/cashier/status",
      { reference },
      {
        headers:{
          Authorization:`Bearer ${process.env.OPAY_SECRET_KEY}`,
          "Content-Type":"application/json"
        }
      }
    );

    if(response.data.status === "SUCCESS"){
      await User.findByIdAndUpdate(userId,{ premium:true });
      return res.json({ success:true });
    }

    res.json({ success:false });

  }catch(err){
    res.status(500).json({ error:"Verification failed"});
  }
});

// Admin Dashboard Data
app.get("/admin/users", async (req,res)=>{
  const users = await User.find();
  res.json(users);
});

app.listen(process.env.PORT, ()=>{
  console.log("Server running on port " + process.env.PORT);
});
