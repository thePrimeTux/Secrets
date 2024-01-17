import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { 
    maxAge: 1000 * 60 * 60 * 24,
  }
}));

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());  

// Error handling
app.use(function(err, req, res, next) {
  console.error(err.stack);
  res.status(err.status || 500).json({ error: err.message });
});

const db = new pg.Client({
    user: process.env.PG_USER,
    host: process.env.PG_HOST,
    database: process.env.PG_DATABASE,
    password: process.env.PG_PASSWORD,
    port: process.env.PG_PORT,
});
db.connect();
 
app.get("/", (req, res) => {
  res.render("home.ejs");
});
 
app.get("/login", (req, res) => {
  res.render("login.ejs");
});
 
app.get("/register", (req, res) => {
  res.render("register.ejs");
});

// app.get("/logout", (req, res) => {
//   req.logout(function (err) {
//     if (err) {
//       return next(err);
//     }
//     res.redirect("/");
//   });
// });

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    const email = req.user.email;
    const result = await db.query(
      "SELECT secret FROM users WHERE email=$1",
      [email]
    );
    res.render("secrets.ejs", {secret:result.rows[0].secret});
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
  scope: ["profile", "email"],
})
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);
 
app.get("/submit", (req, res) => {
  if (req.isAuthenticated){
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
  
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    res.redirect("/");
  });
})

// app.post(
//   "/login", 
//   passport.authenticate("local", {
//   successRedirect: "/secrets",
//   failureRedirect: "/login",
//   })
// );

app.post("/login", function(req, res, next) {
  passport.authenticate("local", function(err, user, info) {
    if (err) { 
      return next(err); 
    }
    if (!user) { 
      const loginError = info.message;  // Set loginError in locals
      return res.render("login.ejs", {loginError});
    }
    req.logIn(user, function(err) {
      if (err) { 
        return next(err); 
      }
      return res.redirect("/secrets");
    });
  })(req, res, next);
});


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

    try {
      const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
        email,
      ]);

      if (checkResult.rows.length > 0) { 
        res.render("register.ejs",{registerError:"Email already registered"});
      } else {
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.error("Error hashing password:", err);
          } else {
            const result = await db.query(
              "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
              [email, hash]
            );
            const user = result.rows[0];
            req.login(user, (err) => {
              console.error(err);
              res.redirect("/secrets");
            });
          }
        });
      }
    } catch (err) {
      console.log(err);
    }
});
 
app.post("/submit", async (req, res) => {
  try {
    const secret = req.body.secret;
    const email = req.user.email;
    const result = await db.query(
      "UPDATE users SET secret = $1 WHERE email = $2",
      [secret, email]);
    res.redirect("/secrets"); 
  } catch (err) {
    console.log(err);
    res.redirect("/login");
  }
  
});

passport.use(
  "local", 
  new Strategy(async function verify(username, password, cb) {  // username and password same as name attribute in ejs file
  try {
    const result = await db.query(
      "SELECT * FROM users WHERE email = $1", 
      [username]
    );
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHash = user.password;
      bcrypt.compare(password, storedHash, (err, valid) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          return cb(err);
        } else {
          if (valid) {
            return cb(null, user);   // isAuthenticated = true
          } else {
            return cb(null, false,{message: "Incorrect password"});      // isAuthenticated = false
          }
        }
      })
    } else {
      return cb(null, false,{message: "Email not registered"});
    }
  } catch (err) {
    return(cb(err));
  }
}));

passport.use(
  "google",
   new GoogleStrategy(
  {
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",   // redirect uri
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  }, 
  async (accessToken, refreshToken, profile, cb) => {
  try {
    // console.log(profile);
    const result = await db.query(
      "SELECT * FROM users WHERE email=$1",
      [profile.email]);
    if (result.rows.length ===0 ) {
      const newUser = await db.query(
        "INSERT INTO users (email,password) VALUES ($1,$2)",
        [profile.email, "google"]);
      return cb(null, newUser.rows[0]);
    } else {
      return cb(null, result.rows[0]);
    }
  } catch (err) {
    return cb(err);
  }
}));

passport.serializeUser((user, cb) => {
  cb(null, user);
});
 
passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});