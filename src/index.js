const express = require("express");
var bodyParser = require("body-parser");
const { Authenticator } = require("beland-crypto");
const { body, validationResult } = require("express-validator");

const app = express();
// parse various different custom JSON types as JSON
app.use(bodyParser.json());

app.post(
  "/crypto/validate-signature",
  body("timestamp").isNumeric().notEmpty(),
  body("auth_chain").isArray({min: 1}).notEmpty(),
  body('auth_chain.*.payload').notEmpty(),
  async (req, res) => {
    // Finds the validation errors in this request and wraps them in an object with handy functions
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const vResust = await Authenticator.validateSignature(
      req.body.timestamp,
      req.body.auth_chain,
      null,
      Date.now()
    );

    res.json({
      valid: vResust.ok,
      ownerAddress: req.body.auth_chain[0].payload.toLowerCase(),
    });
  }
);
const port = process.env.PORT || 5050;
app.listen(port);
console.log(`> crypto-validate-signature running! (:${port})`);
