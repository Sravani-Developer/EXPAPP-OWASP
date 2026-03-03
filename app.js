const express = require("express"),
  expSession = require("express-session"),
  app = express(),
  mongoose = require("mongoose"),
  passport = require("passport"),
  bodyParser = require("body-parser"),
  LocalStrategy = require("passport-local"),
  User = require("./models/user"),
  mongoSanitize = require("express-mongo-sanitize"),
  xss = require("xss-clean"),
  rateLimit = require("express-rate-limit"),
  helmet = require("helmet");

// DB
mongoose.connect("mongodb://localhost/auth_demo");

// Session
app.use(
  expSession({
    secret: "mysecret",
    resave: false,
    saveUninitialized: true,
    cookie: {
      httpOnly: true,
      secure: false, // keep FALSE for localhost testing
      maxAge: 1 * 60 * 1000, // 1 minute (keep as PDF shows)
    },
  })
);


// Passport
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser(User.serializeUser()); // session encoding
passport.deserializeUser(User.deserializeUser()); // session decoding
passport.use(new LocalStrategy(User.authenticate()));

// App middleware
app.set("view engine", "ejs");
app.use(
  bodyParser.urlencoded({
    extended: true,
  })
);
app.use(express.static("public"));

//      O W A S P

// Helmet to secure headers
app.use(helmet());

// Data Sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());

// Data Sanitization against XSS attacks
app.use(xss());

// Preventing DOS Attacks - Body limit
app.use(express.json({ limit: "10kb" }));

// Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "Too many requests",
});

// Apply limiter to login route
app.use("/login", limit);

//      R O U T E S
app.get("/", (req, res) => {
  res.render("home");
});

function isLoggedIn(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  return res.redirect("/login");
}

// Protect profile page
app.get("/userprofile", isLoggedIn, (req, res) => {
  res.render("userprofile");
});

// Auth Routes
app.get("/login", (req, res) => {
  res.render("login");
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/userprofile",
    failureRedirect: "/login",
  })
);

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  try {
    await User.register(
      new User({
        username: req.body.username,
        email: req.body.email,
        phone: req.body.phone,
      }),
      req.body.password
    );

    return res.redirect("/login");
  } catch (err) {
    console.log("REGISTER ERROR:", err);

    if (
      err &&
      (err.name === "UserExistsError" ||
        (err.message && err.message.includes("already registered")))
    ) {
      return res.render("register");
    }

    return res.render("register");
  }
});

app.get("/logout", (req, res, next) => {
  req.logout(function (err) {
    if (err) return next(err);
    res.redirect("/");
  });
});

// Listen
const PORT = process.env.PORT || 3001;
app.listen(PORT, function (err) {
  if (err) {
    console.log(err);
  } else {
    console.log(`Server Started At Port ${PORT}`);
  }
});
