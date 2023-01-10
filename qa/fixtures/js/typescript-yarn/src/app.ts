"use strict";

import * as express from "express";
import * as crypto from "crypto";

const app: express.Application = express();

app.get("/", (req, res) => {
  res.send("Hello!");
});

// Detects HTML injections - tsr-detect-html-injection
app.get("./html_injection", (req, res) => {
  var elem: HTMLElement = new HTMLElement
  elem.innerHTML = req.params.content;
  res.send(elem);
});

// Possible timing attack - tsr-detect-possible-timing-attacks
app.get("/timing-attack", (req, res) => {
  var auth: string = "password";
  var userInput: string = req.params.password;

  if (userInput == auth) {
    res.send("authenticated");
  } else {
    res.send("forbidden");
  }
});

// Non-literal Regexp - tsr-detect-non-literal-regexp
app.get("/user-supplied-regex", (req, res) => {
  var myregexpText: string = req.params.regex;
  var myregexp: RegExp = new RegExp(myregexpText);

  res.send(myregexp.test("(x+x+)+y"));
});

// tsr-detect-pseudo-random-bytes
app.get("/random", (req, res) => {
  var randomishNumber = crypto.pseudoRandomBytes
  res.send(randomishNumber);
});

// Eval with variable - tsr-detect-eval-with-expression
app.get("/eval", (req, res) => {
  eval(req.params.expression);
  res.send("I did whatever you asked");
});

const server = app.listen(3000, () => {
  console.log("  App is running at http://localhost:3000");
});

export default server;
