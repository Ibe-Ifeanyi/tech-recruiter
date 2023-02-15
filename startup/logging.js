const winston = require("winston");
require("express-async-errors");

module.exports = function () {
  // Handle uncaught exceptions - exceptions that occur outside the request processing pipeline (that is, outside the context of Express)
  winston.handleExceptions(
    new winston.transports.File({ filename: "uncaughtExceptions.log" }),
    new winston.transports.Console({
      colorize: true,
      prettyPrint: true,
    })
  );

  process.on("unhandledRejection", (ex) => {
    throw ex;
  });

  winston.add(winston.transports.File, { filename: "recruitr_logs.log" });
};
