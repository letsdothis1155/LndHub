process.on('uncaughtException', function (err) {
  console.error(err);
  console.log('Node NOT Exiting...');
});

let express = require('express');
const helmet = require('helmet');
let morgan = require('morgan');
import { v4 as uuidv4 } from 'uuid';
let logger = require('./utils/logger');
const config = require('./config');

morgan.token('id', function getId(req) {
  return req.id;
});

let app = express();

// Off unless explicitly configured: with it on, req.ip is taken from a header
// the client controls, so rate limits can be sidestepped by rotating
// X-Forwarded-For. Set TRUST_PROXY=1 (or the real hop count) when running
// behind a reverse proxy. See utils/trustProxy.js.
const { parseTrustProxy } = require('./utils/trustProxy');
app.set('trust proxy', parseTrustProxy(process.env.TRUST_PROXY));

// Security headers. CSP allows only same-origin resources; inline style= is
// required for the progress-bar width attribute in the dashboard template.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    crossOriginEmbedderPolicy: false,
  }),
);

const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: config.rateLimit || 200,
});
app.use(limiter);

app.use(function (req, res, next) {
  req.id = uuidv4();
  next();
});

app.use(
  morgan(
    ':id :remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent"',
  ),
);

let bodyParser = require('body-parser');

app.use(bodyParser.urlencoded({ extended: false })); // parse application/x-www-form-urlencoded
app.use(bodyParser.json(null)); // parse application/json

app.use('/static', express.static('static'));
app.use(require('./controllers/api'));
app.use(require('./controllers/website'));

const bindHost = process.env.HOST || '0.0.0.0';
const bindPort = process.env.PORT || 3000;

let server = app.listen(bindPort, bindHost, function () {
  logger.log('BOOTING UP', 'Listening on ' + bindHost + ':' + bindPort);
  logger.log('using GroundControl', process.env.GROUNDCONTROL);
});
module.exports = server;
