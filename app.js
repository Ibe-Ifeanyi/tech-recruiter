require("dotenv").config();

const Joi = require("joi");
Joi.objectId = require("joi-objectid")(Joi);
const express = require("express");
const { logger } = require("./middleware/logger");
const helmet = require("helmet");
const winston = require("winston");
const cookieParser = require("cookie-parser");

const app = express();

const { PORT } = process.env;

app.use(helmet());
app.use(express.json());
app.use(cookieParser(process.env.JWT_SECRET));
app.use(logger);

require("./startup/logging")();
require("./startup/routes")(app);
require("./startup/db")();
require("./startup/config")(app);

app.listen(PORT, winston.info(`App is listening on port ${PORT}`));
