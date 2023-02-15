const express = require("express");
const userRoutes = require("../routes/auth");
const errorHandler = require("../middleware/error");

module.exports = function (app) {
  app.use("/api/v1/users", userRoutes);
  app.use(errorHandler);
};
