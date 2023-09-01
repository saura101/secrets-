//jshint esversion:6
import "dotenv/config";
import express from "express";
import bodyParser from "body-parser";
import mongoose from "mongoose";
import encrypt from "mongoose-encryption";
import md5 from "md5";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import passportLocalMongoose from "passport-local-mongoose";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import findOrCreate from "mongoose-findorcreate";

const saltRounds = 10;

const app = express();
const PORT = 3000;

//console.log(process.env.SECRET);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended : true}));

//this is where we need to place session middleware
app.use(session({               
    secret : "our little secret.",
    resave : false,
    saveUninitialized : false
}));

app.use(passport.initialize());
app.use(passport.session());

await mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new mongoose.Schema ({
    // email : {
    //     type : String,
    //     required : [true, "username required"]
    // },
    // password : {
    //     type : String,
    //     required : [true,"password required"]
    // }

    email : String,
    password : String,
    googleId : String
});

const secretSchema = new mongoose.Schema ({
    secret : String
});

// const secret =process.env.SECRET;
// userSchema.plugin(encrypt, {secret : secret, encryptedFields : ["password"]});

//passport local mongoose plugin to hash and salt passwords
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User",userSchema);
const Secret = mongoose.model("secret",secretSchema);

passport.use(User.createStrategy());


//this is defined in passport local mongoose
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//passport docs serialize and deserialize
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", (req,res) => {
    res.render("home.ejs");
    console.log(req.session);
    console.log(req.sessionID);
});

app.get("/auth/google", passport.authenticate("google", { 
    scope : ["profile"]  
}));

app.get("/auth/google/secrets", 
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get("/login", (req,res) => {
    res.render("login.ejs");
});

app.get("/register", (req,res) => {
    res.render("register.ejs");
});

app.get("/secrets", async(req,res) => {
    if(req.isAuthenticated()) {
        const data = await Secret.find({});
        console.log(data);
        res.render("secrets.ejs", {secrets : data});
    } else {
        res.redirect("/login");
    }
})

app.get("/submit" ,(req,res) => {
    if(req.isAuthenticated()) {
        res.render("submit.ejs");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout" ,(req,res) => {
    req.logout((err)=> {
        if(err) {
            console.log(err);
        }
        res.redirect("/");
    });
    
});

app.post("/submit" ,async(req,res) => {
    const submittedSecret = req.body.secret;
    console.log(req.user);
    const secret = new Secret ({
        secret : req.body.secret
    });
    await secret.save();
    res.redirect("/secrets");
});

app.post("/register" ,async(req,res) => {
    
    //const hash = await bcrypt.hash(req.body.password,saltRounds);

    // const user = new User ({
    //     email : req.body.username,
    //     //password : md5(req.body.password)
    //     password : hash
    // });

    // try {
    //     await user.save();
    //     res.render("secrets.ejs");
    // }catch(error) {
    //     console.log(error.message);
    //     res.render("register.ejs", {err: error.message});
    // }

    //using pasport local mongoose
    User.register({ username : req.body.username}, req.body.password, (err, user)=> {
        if(err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req,res , ()=> {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login" ,passport.authenticate("local"),async(req,res) => {
    
    // const username = req.body.username;
    // //const password = md5(req.body.password);
    // const password = req.body.password;

    // const user = await User.findOne({ email : username});
    // if(!user) {
    //     res.render("login.ejs", {err: "wrong username or password"});
    // } else {

    //     const match = await bcrypt.compare(password, user.password);
    //     if(match) {
    //         res.render("secrets.ejs");
    //     } else {
    //         res.render("login.ejs", {err: "wrong username or password"});
    //     }
    // }
    
    //using passport local mongoose
    res.redirect("/secrets");
    
});

app.listen(PORT, ()=> {
    console.log(`server is running on port ${PORT}`);
})