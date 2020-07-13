const data = require("../data");
const usersData = data.users;
const bcrypt = require("bcrypt");
//const session = require('express-session');

const constructorMethod = app => {

app.use(function(req, res, next){

  let requestLog = "[" + new Date().toUTCString() + "]: " + req.method + " " + req.originalUrl;
  if(!req.session.isAuthenticated){

    requestLog = requestLog + " (Not Authenticated)";
  }
  else
    requestLog = requestLog + " (Authenticated)";
  console.log(requestLog);  
  next();
});

app.get("/", async (req, res) => {
    try{
      if(req.session.userlogged == undefined || req.session.userlogged == null){
        req.session.isAuthenticated = false; 
        res.render("login", {});
      }
      else{
        req.session.isAuthenticated = true; 
        res.redirect("/private");
      }        
    }
    catch(e){ 
      res.status(404).render("login", {errors: "Invalid Request", hasErrors: true});   
    }
});



app.post("/login", async (req, res) => {
    try {
      if(!req.body){
        res.status(404).render("login", {errors: "Invalid Request", hasErrors: true});  
      }
      if(!req.body.username){
        res.status(404).render("login", {errors: "Invalid Request", hasErrors: true}); 
      }
      if(!req.body.password){
        res.status(404).render("login", {errors: "Invalid Request", hasErrors: true}); 
      }
      let user = {userName: req.body.username, password: req.body.password }
      console.log("UserName: " + user.userName);
      console.log("Password: " + user.password);    

      let result = await usersData.getUser(user.userName);
      if(result === undefined || result === null || result.length == 0){
        res.status(401).render("login", {errors : "Provide a valid username and/or password.", hasErrors: true});
      }
      else{
      let hashed = await bcrypt.compare(user.password, result.hashedPassword);
      if(hashed){
        req.session.isAuthenticated = true;         
        req.session.userlogged = result;
        res.redirect("/private");
      }        
      else
        res.status(401).render("login", {errors : "Provide a valid username and/or password.", hasErrors: true});
    }
    }
    catch(e) { 
      res.status(404).render("login", {errors: "Invalid Request", hasErrors: true});    
    }
});


app.get("/logout", async (req, res) => {
  try{
      res.clearCookie("AuthCookie");
      req.session.userlogged = null;
      req.session.isAuthenticated = false;  
      res.render("logout", {message : "You logged out successfully"});
  }
  catch(e)
  {    
    res.status(404).render("login", {errors: "Invalid Request", hasErrors: true});     
}

// app.get("/logout", (req, res) => {
//   //expire the AuthCookie and inform the user that they have been logged out
//   res.clearCookie('AuthCookie');

//   //It will provide a URL to the / route
//   res.redirect('/login');
//   console.log("you are logged out");
});


const logRequest = async(req, res, next)=>{
    if(req.session.userlogged == null || req.session.userlogged == undefined){

      res.status(403).render("login", {});       
    }else{

      next();   
    }   
};

app.get("/private", logRequest, async (req, res) => {


    try {
      res.render("private", {sessionData : req.session.userlogged}); 
    }
    catch(e){ 
      res.status(404).render("login", {errors: "Invalid Request", hasErrors: true}); 
    }
});

app.get("*", async (req, res) => {
 
  res.redirect("/");
});
};
module.exports = constructorMethod;
