const mongoose = require("mongoose");
const winston = require("winston");

module.exports = function () {
  mongoose.set("strictQuery", false);

  mongoose
    .connect(process.env.DB_URL)
    .then(() => winston.info("Connected to the database..."));
};
