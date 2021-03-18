# Steps to make your own NPM package.

1. **Copy this npm-template** and rename it to something you like.
2. **Add a new job under [npm in Jenkins](https://build.sys.kth.se/view/npm/)**. Copy an existing npm job like _npm-template_, Name it to the same name as your repository.
3. Under _configuration_ in the new job **change Git URL and Git repo-name**.
4. **Add the build to [Travis CI](https://travis-ci.org/organizations/KTH/repositories)**
5. **Remove this orderd list** from your README.md and update the stuff below with your package information.
6. 💥 🎉 Happy Coding!

**Publishing to npm is now automatic**. Every time you push Evolene will run `npm run-script build`. After that Evolene will check to see if the version in package.json is newer then on npm.com. If so, a new version is published to npm.

*Reminder:* If you forget to update the version Evolene will run npm run-script build, but *without publishing* to the registy.


# NPM Template ![alt text](https://api.travis-ci.org/KTH/npm-template.svg?branch=master)

NPM: https://www.npmjs.com/package/@kth/npm-template

## How to use

```javascript
const package = require("npm-template");

if (package.isWorking()) {
  console.log("Hello World!");
}
```

## Run tests

```bash
npm build ## Does npm install and npm test.
```

You can also view the tests at https://travis-ci.org/KTH/npm-template

### Output from tests

```text

Type of tests header
   ✓ When running tests, expect it to always return 'true'.

```
