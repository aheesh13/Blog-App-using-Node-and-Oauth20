//jshint esversion:6
require('dotenv').config();
const express=require("express");
const bodyParser=require("body-parser");
const ejs=require("ejs");
const mongoose=require("mongoose");
const session=require("express-session");
const passport=require("passport");
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate=require('mongoose-findorcreate');

const app=express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//To use the express session.
app.use(session({
  secret:"Our Secret.",
  resave:false,
  saveUninitialized: false
}));
//sets up passport to use for authentication
app.use(passport.initialize());
//use passport to deal with the sessions
app.use(passport.session());

mongoose.connect(process.env.MONGO_CONNECT,{useNewUrlParser:true});
//if there are any warnings then set this useCreateIndex to true.


const userSchema= new mongoose.Schema ({
  email: String,
  password:String,
  googleId: String,
  title: String,
  content:String

});

//use this passportLocalMongoose plugin to hash and salt the password and to save users into mongoDb
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);


const User=new mongoose.model("User", userSchema);

//using the passportLocalMongoose plugin we create a strategy
passport.use(User.createStrategy());

//creates cookie and stuffs the details of user/login creds
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
// Descrambles the cookie and gets the details of user/login creds
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

//we need to get the client id and client secret from google cloud platform when we create our web app and link with google
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    useProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  //acess token is given to our webapp by google servers to get any additional info on users in future
  //find the user if the google id matches with database or create user if there is no user in DB.
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req,res){
  res.render("home");
});
//passport authenticates the google ie: google strategy written above and requests for user profile info
//Once the button is triggered it makes a get req to auth/google and initiate authentication on google servers asking for user profle once they logged in.
app.get("/auth/google",
  passport.authenticate('google', { scope: ["profile"] })
);

//after logging in or registering the user, google redirect route will be /auth/google/secrets if authenticated then redirect to secrets route.
app.get("/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/login" }),
  function(req, res) {
    // Successful authentication, redirect screts.
    res.redirect("/secrets");
  });


app.get("/login", function(req,res){
  res.render("login");
});

//Once you are authenticated and go to the secrets page, when you click on submit your secret button it has a
//href of /submit
app.get("/submit", function(req,res){
  if(req.isAuthenticated()){
    res.render("submit");
  }
  else{
    res.redirect("/login");
  }
});

app.get("/posts/:postId", function(req, res){
  const requestedPostId = req.params.postId;
   User.findOne({_id:requestedPostId},function(err,post){
     res.render("post", {
       title: post.title,
       content: post.content
     });
   });
 });
//After you render the submit ejs page,a button with a name secret will make post request to /submit route.
app.post("/submit", function(req,res){
  const submittedtitle=req.body.title;
  const submittedcontent=req.body.content;
  // passport has a method to find the current user using the session.
  console.log(req.user.id);

  User.findById(req.user.id, function(err, found){
    if(err){
      console.log(err);
    }else{
      if(found){
        found.title = submittedtitle;
        found.content=submittedcontent
        found.save(function(){
          res.redirect("/secrets");
        });
      }
    }
  });
});

app.post("/delete", function(req,res){
const clickedItemId=req.body.delete;

User.findByIdAndRemove(clickedItemId, function(err){
  if(!err){
    console.log("Successfully deleted the selected item");
    res.redirect("/secrets");
  }
});
});
//Logut is used to deauthenticate the users. req.logut is a passsport function.
app.get("/logout", function(req,res){
  req.logout();
  res.redirect("/");
});

app.get("/about", function(req,res){
  res.render("about");
});

app.get("/contact", function(req,res){
  res.render("contact");
});

app.get("/register", function(req,res){
  res.render("register");
});

app.get("/secrets", function(req,res){

 User.find({"title": {$ne:null},"content": {$ne:null}}, function(err,foundUsers){
   if(err){
     console.log(err);
   }else{
     if(foundUsers){
       res.render("secrets", {usersWithSecrets: foundUsers});
     }
   }
 });


  // if(req.isAuthenticated()){
  //   res.render("secrets");
  // }//If the user is not authenticated or if user tries to access the secrets page after closing the current session.
  // else{
  //   //cookie is set to expire when the browser is closed
  //   // The user will be redirected to login page if user closes the current session
  //   res.redirect("/login");
  // }
});

app.post("/register", function(req,res){
//User is the mongodb model name and reigister is the passportLocalMongoose plugin.
//the password will be salted and hashed and sent to DB
 User.register({username:req.body.username}, req.body.password, function(err,user){
   if(err){
     console.log(err);
     res.redirect("/register");
   }else{
     passport.authenticate("local")(req,res,function(){  //if there is no error then the user is authenticated using local and if success then user is redirected to secrets page.
       res.redirect("/secrets");
     });
   }


 });
});

app.post("/login", function(req,res){

user=new User({
  username: req.body.username,
  password: req.body.password
});
//req.login is a passport-local plugin fuction used to authenticate the users while logging in
req.login(user,function(err){
  if(err){
    console.log(err);
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
});
});
let port=process.env.PORT;
if(port==null || port==""){
  port=3000;
}

app.listen(port, function(){
  console.log("Server has started successfully. ");
});
