const morgan = require("morgan");

module.exports = function (app) {
  if (!process.env.JWT_SECRET) {
    throw new Error("FATAL ERROR: JWT_SECRET environment variable is not set.");
  }

  if (app.get("env") === "development") {
    app.use(morgan("tiny"));
    console.log("Morgan enabled!");
  }
};
