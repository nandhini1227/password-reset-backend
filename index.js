const express = require("express");
const app = express();
const mongodb = require("mongodb");
const mongoClient = mongodb.MongoClient;
const dotenv = require("dotenv").config;
const cors = require("cors");
var nodemailer = require("nodemailer");
var randomstring = require("randomstring");

const URL = process.env.DB;

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");


app.use(express.json());
app.use(
  cors({
    origin: "*",
  })
);

let authenticate = function (request, response, next) {
  // console.log(request.headers);
  if (request.headers.authorization) {
    let verify = jwt.verify(request.headers.authorization, process.env.SECRET);
    console.log(verify);
    if (verify) {
      request.userid = verify.id;

      next();
    } else {
      response.status(401).json({
        message: "Unauthorized",
      });
    }
  } else {
    response.status(401).json({
      message: "Unauthorized",
    });
  }
};

async function connectToDB(operation) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const result = await operation(db);
    await connection.close();
    return result;
  } catch (error) {
    console.error(error);
    throw error; 
  }
};

app.post("/register", async function (request, response) {
  try {
    await connectToDB(async (db) => {
      const salt = await bcrypt.genSalt(10);
      const hash = await bcrypt.hash(request.body.password, salt);
      request.body.password = hash;
      await db.collection("users").insertOne(request.body);
    });
    response.json({
      message: "User Registered!",
    });
  } catch (error) {
    response.status(500).json({ message: "Error during registration" });
  }
});

app.post("/", async function (request, response) {
  try {
    const user = await connectToDB(async (db) =>
      db.collection("users").findOne({ username: request.body.username })
    );

    if (user) {
      const match = await bcrypt.compare(request.body.password, user.password);
      if (match) {
        
        const token = jwt.sign(
          { id: user._id, username: user.username },
          process.env.SECRET
        );
        response.json({
          message: "Successfully Logged In!!",
          token,
        });
      } else {
        response.json({
          message: "Password is incorrect!!",
        });
      }
    } else {
      response.json({
        message: "User not found",
      });
    }
  } catch (error) {
    response.status(500).json({ message: "Error during login" });
  }
});

app.post("/dashboard", authenticate, async function (request, response) {
  try {
    await connectToDB(async (db) => {
      request.body.userid = mongodb.ObjectId(request.userid);
      await db.collection("data").insertOne(request.body);
    });
    response.json({
      message: "Data added!!",
    });
  } catch (error) {
    response.status(500).json({ message: "Error adding data" });
  }
});

app.get("/dashboard", authenticate, async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    let userdata = await db
      .collection("data")
      .find({ userid: mongodb.ObjectId(request.userid) })
      .toArray();
    await connection.close();
    response.json(userdata);
  } catch (error) {
    console.log(error);
  }
});

app.post("/resetpassword", async function (request, response) {
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      let mailid = request.body.email;
      let rString = randomstring.generate(7);
      let link = "https://password-reset-front-end.vercel.app/reset-password-page";
      await db
        .collection("users")
        .updateOne({ email: mailid }, { $set: { rString: rString } });
      await connection.close();

      var transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: "testnodemail04@gmail.com",
          pass: process.env.pass,
        },
      });

      var mailOptions = {
        from: "testnodemail04@gmail.com",
        to: mailid,
        subject: "Password Reset",
        text: `Your Random text is ${rString}. Click the link to reset password ${link}`,
        html: `<h2> Your Random text is ${rString}. Click the link to reset password ${link}</h2>`,
      };

      transporter.sendMail(mailOptions, function (error, info) {
        if (error) {
          console.log(error);
          response.json({
            message: "Email not send",
          });
        } else {
          console.log("Email sent: " + info.response);
          response.json({
            message: "Email Send",
          });
        }
      });
      response.json({
        message: "Email Send",
      });
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/reset-password-page", async function (request, response) {
  let mailid = request.body.email;
  let String = request.body.rString;
  try {
    const connection = await mongoClient.connect(URL);
    const db = connection.db("passwordReset");
    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(request.body.password, salt);
    request.body.password = hash;
    const user = await db
      .collection("users")
      .findOne({ email: request.body.email });
    if (user) {
      if (user.rString === request.body.rString) {
        await db
          .collection("users")
          .updateOne(
            { rString: String },
            { $set: { password: request.body.password } }
          );
        response.json({
          message: "Password reset done",
        });
      } else {
        response.json({
          message: "Random String is incorrect",
        });
      }
    } else {
      response.json({
        message: "Email Id not match / User not found",
      });
    }
    await db
      .collection("users")
      .updateOne({ rString: String }, { $unset: { rString: "" } });
  } catch (error) {
    console.log(error);
  }
});

app.listen(process.env.PORT || 3003);
