
##### 1.3.2 / 2015-07-06

- update dependencies

##### 1.3.1 / 2015-06-30

- update dependencies
- use make instead grunt
- use eslint
- add node 0.12 to travis

##### 1.3.0 / 2014-09-27

- update dependencies

##### 1.2.0 / 2014-07-23

- add events `'forgot::sent'` and `'forgot::success'`
- update dependencies

##### 1.1.1 / 2014-05-27

- set `autocomplete="off"`
- use Bootstrap responsive classes

##### 1.1.0 / 2014-05-23

- refactor code
- update dependencies
- use updated [lockit-sendmail](https://github.com/zeMirco/lockit-sendmail)

##### 1.0.0 / 2014-04-19

- requires Express 4.x
- makes use of `express.Router()`. No need to pass `app` around as argument.

  **old**

  ```js
  var ForgotPassword = require('lockit-forgot-password');

  var forgotPassword = new ForgotPassword(app, config, adapter);
  ```

  **new**

  ```js
  var ForgotPassword = require('lockit-forgot-password');

  var forgotPassword = new ForgotPassword(config, adapter);
  app.use(forgotPassword.router);
  ```

- proper Error handling. All Errors are piped to next middleware.

  **old**

  ```js
  if (err) console.log(err);
  ```

  **new**

  ```js
  if (err) return next(err);
  ```

  Make sure you have some sort of error handling middleware at the end of your
  routes (is included by default in Express 4.x apps if you use the `express-generator`).

##### 0.5.0 / 2014-04-11

- `username` becomes `name`
