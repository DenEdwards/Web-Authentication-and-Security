require("dotenv").config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const md5 = require("md5");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

const User = mongoose.model("User", userSchema);

app.get("/", function(req,res){
  res.render("home");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.post("/register", function(req,res){
  const username = req.body.username;
  const password = md5(req.body.password);

  const newUser = new User({
    email: username,
    password: password
  });
  newUser.save(function(err){
    if(err){
      console.log(err);
    }else{
      console.log("New User Created!");
      res.render("secrets");
    }
  });
});

app.get("/login", function(req,res){
  res.render("login");
});

app.post("/login", function(req,res){
  const username = req.body.username;
  const password = md5(req.body.password);
  User.findOne({email: username}, function(err, foundResult){
    if(!err){
      if(foundResult){
        if(foundResult.password === password){
          res.render("secrets");
        }else{
          res.redirect("login");
        }
      }else{
        res.redirect("login");
      }
    }else{
      console.log(err);
    }
  });
});

app.listen(3000, function(){
    console.log("Server started on localhost:3000...");
})
